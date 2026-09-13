"""نماذج البيانات العامة لنظام PhishGuard."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class Finding:
    """مؤشر أمني واحد تم اكتشافه أثناء الفحص."""

    code: str
    title: str
    detail: str
    points: int
    severity: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """النتيجة الموحدة لجميع أنواع الفحص."""

    target: str
    target_type: str
    verdict: str
    risk_score: int
    confidence: int
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["findings"] = [finding.to_dict() for finding in self.findings]
        return payload

    @property
    def is_actionable(self) -> bool:
        return self.verdict in {"HIGH_RISK", "CRITICAL"}


def verdict_for_score(score: int) -> str:
    """تحويل درجة الخطر إلى قرار واضح للمستخدم."""
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH_RISK"
    if score >= 25:
        return "SUSPICIOUS"
    return "SAFE"


def confidence_for_score(score: int, finding_count: int) -> int:
    """حساب ثقة تفسيرية، وليست احتمالاً إحصائياً."""
    if finding_count == 0:
        return 92 if score == 0 else 55
    return min(98, 55 + min(35, score // 2) + min(8, finding_count))
