"""قواعد كشف التصيد؛ كل قاعدة تعيد نتيجة قابلة للتفسير."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .models import Finding


@dataclass(frozen=True)
class RuleContext:
    value: str
    parsed_url: Optional[object] = None


Rule = Callable[[RuleContext], Optional[Finding]]

# كلمات شائعة في حملات التصيد، مع تجنب الاعتماد على قائمة خارجية.
URGENCY_WORDS = (
    "urgent", "immediately", "verify", "suspended", "expire", "limited",
    "عاجل", "فوراً", "تحقق", "موقوف", "ينتهي", "محدود",
)
CREDENTIAL_WORDS = (
    "password", "passwd", "login", "signin", "account", "credential",
    "كلمة المرور", "تسجيل الدخول", "الحساب", "بيانات الدخول",
)
PAYMENT_WORDS = (
    "payment", "invoice", "bank", "card", "wallet", "billing",
    "الدفع", "فاتورة", "بنك", "بطاقة", "محفظة",
)
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
}
SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "gq", "tk", "ml", "ga", "cf"}
BRAND_NAMES = {
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "linkedin", "bank", "بنك",
}


def _has_any(value: str, words: Iterable[str]) -> bool:
    lowered = value.casefold()
    return any(word.casefold() in lowered for word in words)


def _hostname(ctx: RuleContext) -> str:
    return (getattr(ctx.parsed_url, "hostname", "") or "").casefold()


def rule_invalid_scheme(ctx: RuleContext) -> Optional[Finding]:
    parsed = ctx.parsed_url
    if parsed and parsed.scheme not in {"http", "https"}:
        return Finding("URL001", "مخطط رابط غير معتاد", "الرابط لا يستخدم HTTP أو HTTPS.", 25, "high")
    return None


def rule_http(ctx: RuleContext) -> Optional[Finding]:
    parsed = ctx.parsed_url
    if parsed and parsed.scheme == "http":
        return Finding("URL002", "اتصال غير مشفّر", "الرابط يستخدم HTTP، لذلك قد تنتقل البيانات دون تشفير.", 18, "high")
    return None


def rule_ip_host(ctx: RuleContext) -> Optional[Finding]:
    host = _hostname(ctx)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return Finding("URL003", "المضيف عنوان IP مباشر", "استخدام عنوان IP بدلاً من اسم نطاق يزيد الشك في صفحات تسجيل الدخول.", 28, "high")


def rule_at_symbol(ctx: RuleContext) -> Optional[Finding]:
    parsed = ctx.parsed_url
    if parsed and "@" in parsed.netloc:
        return Finding("URL004", "رمز @ داخل الرابط", "قد يخفي الجزء السابق للرمز @ هوية المضيف الحقيقي.", 30, "critical")
    return None


def rule_excessive_subdomains(ctx: RuleContext) -> Optional[Finding]:
    host = _hostname(ctx)
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        return Finding("URL005", "نطاقات فرعية كثيرة", "عدد كبير من النطاقات الفرعية قد يستخدم لتقليد نطاق علامة تجارية.", 16, "medium")
    return None


def rule_punycode(ctx: RuleContext) -> Optional[Finding]:
    host = _hostname(ctx)
    if "xn--" in host:
        return Finding("URL006", "نطاق Punycode", "قد يسمح النطاق المشفر بحروف متشابهة بصرياً مع نطاق موثوق.", 24, "high")
    return None


def rule_shortener(ctx: RuleContext) -> Optional[Finding]:
    host = _hostname(ctx)
    if host in SHORTENER_HOSTS:
        return Finding("URL007", "خدمة اختصار روابط", "الرابط المختصر يخفي الوجهة النهائية ويحتاج إلى تحقق إضافي.", 20, "medium")
    return None


def rule_suspicious_tld(ctx: RuleContext) -> Optional[Finding]:
    host = _hostname(ctx)
    labels = host.split(".")
    if labels and labels[-1] in SUSPICIOUS_TLDS:
        return Finding("URL008", "امتداد نطاق مرتفع الخطورة", "امتداد النطاق شائع في الروابط منخفضة الثقة أو المؤقتة.", 15, "medium")
    return None


def rule_long_url(ctx: RuleContext) -> Optional[Finding]:
    if len(ctx.value) > 140:
        return Finding("URL009", "رابط طويل جداً", "طول الرابط قد يخفي مساراً أو معاملات مصممة لتضليل المستخدم.", 12, "low")
    return None


def rule_encoded_url(ctx: RuleContext) -> Optional[Finding]:
    if "%" in ctx.value or "%2f" in ctx.value.casefold() or "%40" in ctx.value.casefold():
        return Finding("URL010", "ترميز خاص داخل الرابط", "استخدام ترميز URL بكثرة قد يصعّب معرفة الوجهة الحقيقية.", 10, "low")
    return None


def rule_brand_mismatch(ctx: RuleContext) -> Optional[Finding]:
    host = _hostname(ctx)
    if not host:
        return None
    host_without_www = host.removeprefix("www.")
    for brand in BRAND_NAMES:
        if brand in host_without_www and not host_without_www.endswith(f"{brand}.com"):
            return Finding("URL011", "تقليد اسم علامة تجارية", f"اسم المضيف يحتوي على كلمة مرتبطة بعلامة تجارية: {brand}.", 22, "high")
    return None


def rule_credential_path(ctx: RuleContext) -> Optional[Finding]:
    parsed = ctx.parsed_url
    if parsed and _has_any(f"{parsed.path}?{parsed.query}", CREDENTIAL_WORDS):
        return Finding("URL012", "مسار يطلب بيانات دخول", "الرابط يوجه إلى مسار مرتبط بالحسابات أو كلمات المرور.", 15, "medium")
    return None


def rule_urgency(ctx: RuleContext) -> Optional[Finding]:
    if _has_any(ctx.value, URGENCY_WORDS):
        return Finding("TXT001", "لغة استعجال أو تهديد", "وجود عبارات استعجال قد يدفع المستخدم لاتخاذ قرار سريع.", 12, "medium")
    return None


def rule_credentials(ctx: RuleContext) -> Optional[Finding]:
    if _has_any(ctx.value, CREDENTIAL_WORDS):
        return Finding("TXT002", "طلب بيانات حساسة", "المحتوى يشير إلى طلب تسجيل الدخول أو كلمة المرور.", 14, "high")
    return None


def rule_payment(ctx: RuleContext) -> Optional[Finding]:
    if _has_any(ctx.value, PAYMENT_WORDS):
        return Finding("TXT003", "موضوع مالي أو دفع", "المحتوى يتضمن مؤشرات مالية تحتاج إلى تحقق مستقل.", 10, "medium")
    return None


def rule_many_links(ctx: RuleContext) -> Optional[Finding]:
    links = re.findall(r"https?://[^\s<>]+", ctx.value, flags=re.IGNORECASE)
    if len(links) >= 4:
        return Finding("TXT004", "روابط متعددة في المحتوى", "وجود روابط كثيرة يزيد مساحة الهجوم ويستدعي مراجعة كل وجهة.", 12, "medium")
    return None


URL_RULES: tuple[Rule, ...] = (
    rule_invalid_scheme, rule_http, rule_ip_host, rule_at_symbol,
    rule_excessive_subdomains, rule_punycode, rule_shortener,
    rule_suspicious_tld, rule_long_url, rule_encoded_url,
    rule_brand_mismatch, rule_credential_path,
)
TEXT_RULES: tuple[Rule, ...] = (rule_urgency, rule_credentials, rule_payment, rule_many_links)


def url_findings(url: str) -> List[Finding]:
    parsed = urlparse(url)
    context = RuleContext(url, parsed)
    findings = [finding for rule in URL_RULES if (finding := rule(context))]
    findings.extend(finding for rule in TEXT_RULES[:3] if (finding := rule(context)))
    return findings


def text_findings(text: str) -> List[Finding]:
    context = RuleContext(text)
    return [finding for rule in TEXT_RULES if (finding := rule(context))]
