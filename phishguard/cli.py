"""واجهة سطر الأوامر الرسمية لـ PhishGuard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, List

from .config import ConfigurationError, configure_logging, load_config
from .models import ScanResult
from .scanner import export_json, scan_csv_file, scan_file, scan_text, scan_url, summarize

VERSION = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="PhishGuard — فاحص محلي ذكي وقابل للتفسير لاكتشاف مؤشرات التصيد.",
        epilog="ملاحظة: الفحص محلي ولا يفتح الروابط أو يرسل المحتوى إلى أي خدمة خارجية.",
    )
    parser.add_argument("--version", action="version", version=f"PhishGuard {VERSION}")
    parser.add_argument("--config", metavar="FILE", help="مسار ملف إعدادات JSON اختياري")
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default=None,
        help="مستوى السجل (الافتراضي WARNING)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True, title="الأوامر")

    scan_parser = subparsers.add_parser("scan", help="فحص رابط أو نص أو ملف")
    scan_parser.add_argument("--config", metavar="FILE", default=argparse.SUPPRESS, help="مسار ملف إعدادات JSON اختياري")
    scan_parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"), default=argparse.SUPPRESS, help="مستوى السجل")
    scan_group = scan_parser.add_mutually_exclusive_group(required=True)
    scan_group.add_argument("--url", help="فحص رابط واحد دون فتحه")
    scan_group.add_argument("--text", help="فحص نص رسالة أو بلاغ")
    scan_group.add_argument("--file", help="فحص ملف نصي مدعوم")
    scan_parser.add_argument("--format", choices=("table", "json", "quiet"), default=None, help="تنسيق النتيجة")
    scan_parser.add_argument("--output", help="حفظ JSON في ملف بدلاً من العرض فقط")

    batch_parser = subparsers.add_parser("batch", help="فحص مجموعة روابط أو نصوص من CSV")
    batch_parser.add_argument("--config", metavar="FILE", default=argparse.SUPPRESS, help="مسار ملف إعدادات JSON اختياري")
    batch_parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"), default=argparse.SUPPRESS, help="مستوى السجل")
    batch_parser.add_argument("csv_file", help="ملف CSV يحتوي عمود url أو target أو link أو text")
    batch_parser.add_argument("--format", choices=("table", "json"), default=None, help="تنسيق النتائج")
    batch_parser.add_argument("--output", help="حفظ النتائج التفصيلية بصيغة JSON")

    init_parser = subparsers.add_parser("init-config", help="إنشاء ملف إعدادات نموذجي")
    init_parser.add_argument("--config", metavar="FILE", default=argparse.SUPPRESS, help="مسار ملف إعدادات JSON اختياري")
    init_parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"), default=argparse.SUPPRESS, help="مستوى السجل")
    init_parser.add_argument("output", nargs="?", default="phishguard.json", help="اسم ملف الإعدادات الناتج")
    return parser


def _risk_label(verdict: str) -> str:
    return {
        "SAFE": "آمن",
        "SUSPICIOUS": "مشبوه",
        "HIGH_RISK": "خطر مرتفع",
        "CRITICAL": "حرج",
    }.get(verdict, verdict)


def _print_result(result: ScanResult) -> None:
    print("=" * 72)
    print(f"الهدف       : {result.target}")
    print(f"النوع       : {result.target_type}")
    print(f"القرار      : {_risk_label(result.verdict)} ({result.verdict})")
    print(f"درجة الخطر  : {result.risk_score}/100")
    print(f"الثقة       : {result.confidence}% — ثقة تفسيرية وليست احتمالاً إحصائياً")
    print(f"المؤشرات    : {len(result.findings)}")
    if result.findings:
        print("\nالمؤشرات المكتشفة:")
        for finding in result.findings:
            print(f"  [{finding.code}] +{finding.points:02d} | {finding.title}: {finding.detail}")
    else:
        print("\nلم تُكتشف مؤشرات تصيد ضمن القواعد المحلية الحالية.")
    print("=" * 72)


def _print_batch(results: List[ScanResult]) -> None:
    stats = summarize(results)
    print(f"تم فحص {stats['total']} عنصر | متوسط الخطر: {stats['average_risk_score']}/100 | عالي الخطورة/حرج: {stats['high_risk_count']}")
    print("التوزيع: " + " | ".join(f"{key}: {value}" for key, value in stats["verdict_distribution"].items()))
    print("\nالنتائج:")
    print(f"{'#':>3}  {'القرار':<12} {'الخطر':>5}  الهدف")
    print("-" * 72)
    for index, result in enumerate(results, start=1):
        target = result.target.replace("\n", " ")
        if len(target) > 48:
            target = target[:45] + "..."
        print(f"{index:>3}  {_risk_label(result.verdict):<12} {result.risk_score:>5}  {target}")


def _write_config(path_text: str) -> None:
    path = Path(path_text).expanduser()
    if path.exists():
        raise FileExistsError(f"الملف موجود مسبقاً: {path}. اختر اسماً آخر حتى لا يتم استبداله.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "output_format": "table",
            "max_file_mb": 5,
            "network_access": False,
            "log_level": "WARNING",
        }, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"تم إنشاء ملف الإعدادات: {path}")


def _scan_from_args(args: argparse.Namespace, config: dict) -> ScanResult:
    if args.url is not None:
        return scan_url(args.url)
    if args.text is not None:
        return scan_text(args.text)
    max_bytes = int(float(config["max_file_mb"]) * 1024 * 1024)
    return scan_file(args.file, max_file_bytes=max_bytes)


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        config = load_config(args.config)
        configure_logging(args.log_level or config["log_level"])
        if args.command == "init-config":
            _write_config(args.output)
            return 0
        if args.command == "scan":
            result = _scan_from_args(args, config)
            output_format = args.format or config["output_format"]
            if args.output:
                export_json([result], args.output)
                print(f"تم حفظ النتيجة في: {args.output}")
            if output_format == "json":
                print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
            elif output_format == "table":
                _print_result(result)
            return 0 if result.verdict in {"SAFE", "SUSPICIOUS"} else 2
        if args.command == "batch":
            max_bytes = int(float(config["max_file_mb"]) * 1024 * 1024)
            results = scan_csv_file(args.csv_file, max_file_bytes=max_bytes)
            if args.output:
                export_json(results, args.output)
                print(f"تم حفظ النتائج في: {args.output}")
            if (args.format or config["output_format"]) == "json":
                print(json.dumps({"summary": summarize(results), "results": [item.to_dict() for item in results]}, ensure_ascii=False, indent=2))
            else:
                _print_batch(results)
            return 2 if any(item.is_actionable for item in results) else 0
        parser.error("الأمر غير معروف.")
    except (ValueError, FileNotFoundError, IsADirectoryError, PermissionError, ConfigurationError, FileExistsError) as exc:
        print(f"خطأ: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print("خطأ: تعذر تنفيذ عملية الملفات بسبب نظام التشغيل أو الصلاحيات.", file=sys.stderr)
        return 1
    except Exception:
        # لا نعرض tracebacks للمستخدم، مع إبقاء exit code واضحاً للبرامج الآلية.
        print("خطأ: حدثت مشكلة غير متوقعة أثناء الفحص. راجع الإدخال أو شغّل --log-level DEBUG.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
