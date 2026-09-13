"""محرك PhishGuard للفحص المحلي الآمن دون مكتبات خارجية."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from .models import Finding, ScanResult, confidence_for_score, verdict_for_score
from .rules import text_findings, url_findings

MAX_FILE_BYTES = 5 * 1024 * 1024
SUPPORTED_TEXT_EXTENSIONS = {".txt", ".eml", ".html", ".htm", ".csv", ".json", ".md", ".log"}


def _score(findings: Iterable[Finding]) -> int:
    # سقف الدرجة يمنع تراكم المؤشرات من إنتاج قيمة غير مفهومة.
    return min(100, sum(max(0, finding.points) for finding in findings))


def _result(target: str, target_type: str, findings: List[Finding], metadata: Optional[Dict[str, Any]] = None) -> ScanResult:
    score = _score(findings)
    return ScanResult(
        target=target,
        target_type=target_type,
        verdict=verdict_for_score(score),
        risk_score=score,
        confidence=confidence_for_score(score, len(findings)),
        findings=findings,
        metadata=metadata or {},
    )


def scan_url(url: str) -> ScanResult:
    """يفحص رابطاً دون فتحه أو إرسال أي بيانات إلى الإنترنت."""
    normalized = url.strip()
    if not normalized:
        raise ValueError("الرابط فارغ.")
    parsed = urlparse(normalized)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("صيغة الرابط غير صحيحة. استخدم مثالاً مثل https://example.com.")
    findings = url_findings(normalized)
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("رقم المنفذ في الرابط غير صحيح.") from exc
    metadata = {
        "scheme": parsed.scheme,
        "hostname": parsed.hostname or "",
        "port": parsed_port,
        "path": parsed.path or "/",
        "query_parameter_count": len(parsed.query.split("&")) if parsed.query else 0,
        "network_access": False,
    }
    return _result(normalized, "url", findings, metadata)


def _extract_urls(text: str) -> List[str]:
    return re.findall(r"https?://[^\s<>\"']+", text, flags=re.IGNORECASE)


def scan_text(text: str, label: str = "inline-text") -> ScanResult:
    """يفحص نصاً مثل رسالة بريد أو بلاغ مستخدم."""
    if not text.strip():
        raise ValueError("النص فارغ.")
    findings = text_findings(text)
    urls = _extract_urls(text)
    per_url: List[Dict[str, Any]] = []
    for url in urls[:20]:
        try:
            url_result = scan_url(url.rstrip(".,);]"))
            findings.extend(url_result.findings)
            per_url.append(url_result.to_dict())
        except ValueError:
            continue
    metadata = {
        "character_count": len(text),
        "url_count": len(urls),
        "urls_analyzed": len(per_url),
        "network_access": False,
        "embedded_urls": per_url,
    }
    return _result(label, "text", findings, metadata)


def _read_text_file(path: Path, max_file_bytes: int = MAX_FILE_BYTES) -> str:
    if not path.exists():
        raise FileNotFoundError(f"الملف غير موجود: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"المسار ليس ملفاً: {path}")
    size = path.stat().st_size
    if size > max_file_bytes:
        limit_mb = max_file_bytes / (1024 * 1024)
        raise ValueError(f"حجم الملف يتجاوز الحد المسموح ({limit_mb:g} MB).")
    if path.suffix.casefold() not in SUPPORTED_TEXT_EXTENSIONS:
        raise ValueError("امتداد الملف غير مدعوم. استخدم txt أو eml أو html أو csv أو json أو md أو log.")
    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("تعذر قراءة الملف كنص UTF-8.") from exc
    except PermissionError as exc:
        raise PermissionError("لا توجد صلاحية لقراءة الملف.") from exc


def scan_file(file_path: str, max_file_bytes: int = MAX_FILE_BYTES) -> ScanResult:
    path = Path(file_path).expanduser()
    text = _read_text_file(path, max_file_bytes=max_file_bytes)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    result = scan_text(text, label=str(path))
    result.target_type = "file"
    result.metadata.update({
        "file_name": path.name,
        "file_extension": path.suffix.casefold(),
        "sha256": digest,
        "size_bytes": path.stat().st_size,
    })
    return result


def scan_csv_file(file_path: str, max_file_bytes: int = MAX_FILE_BYTES) -> List[ScanResult]:
    """يفحص عمود url أو target في ملف CSV ويعيد نتائج متعددة."""
    path = Path(file_path).expanduser()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"الملف غير موجود: {path}")
    if path.stat().st_size > max_file_bytes:
        limit_mb = max_file_bytes / (1024 * 1024)
        raise ValueError(f"حجم الملف يتجاوز الحد المسموح ({limit_mb:g} MB).")
    results: List[ScanResult] = []
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                raise ValueError("ملف CSV لا يحتوي على رؤوس أعمدة.")
            field = next((candidate for candidate in ("url", "target", "link", "text") if candidate in reader.fieldnames), None)
            if not field:
                raise ValueError("أضف عموداً باسم url أو target أو link أو text.")
            for index, row in enumerate(reader, start=2):
                value = (row.get(field) or "").strip()
                if not value:
                    continue
                try:
                    item = scan_url(value) if field != "text" and urlparse(value).scheme else scan_text(value, label=f"{path}:{index}")
                except ValueError as exc:
                    item = _result(f"{path}:{index}", "csv-row", [Finding("INPUT001", "إدخال غير صالح", str(exc), 0, "low")])
                item.metadata.update({"source_file": str(path), "row": index, "column": field})
                results.append(item)
    except UnicodeDecodeError as exc:
        raise ValueError("تعذر قراءة CSV كترميز UTF-8.") from exc
    return results


def summarize(results: Iterable[ScanResult]) -> Dict[str, Any]:
    result_list = list(results)
    distribution: Dict[str, int] = {key: 0 for key in ("SAFE", "SUSPICIOUS", "HIGH_RISK", "CRITICAL")}
    for item in result_list:
        distribution[item.verdict] = distribution.get(item.verdict, 0) + 1
    return {
        "total": len(result_list),
        "average_risk_score": round(sum(item.risk_score for item in result_list) / len(result_list), 2) if result_list else 0,
        "verdict_distribution": distribution,
        "high_risk_count": sum(item.is_actionable for item in result_list),
    }


def export_json(results: Iterable[ScanResult], output: str) -> None:
    path = Path(output).expanduser()
    payload = [result.to_dict() for result in results]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except PermissionError as exc:
        raise PermissionError("لا توجد صلاحية للكتابة في ملف النتائج.") from exc
