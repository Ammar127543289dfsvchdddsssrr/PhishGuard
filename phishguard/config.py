"""إدارة إعدادات PhishGuard باستخدام JSON ومكتبات Python القياسية."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "output_format": "table",
    "max_file_mb": 5,
    "network_access": False,
    "log_level": "WARNING",
}


class ConfigurationError(ValueError):
    """خطأ مفهوم للمستخدم في ملف الإعدادات."""


def load_config(path: str | None) -> Dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    if not path:
        return config
    config_path = Path(path).expanduser()
    if not config_path.exists():
        raise FileNotFoundError(f"ملف الإعدادات غير موجود: {config_path}")
    try:
        loaded = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigurationError("ملف الإعدادات ليس JSON صالحاً.") from exc
    except UnicodeDecodeError as exc:
        raise ConfigurationError("ملف الإعدادات يجب أن يكون بترميز UTF-8.") from exc
    except PermissionError as exc:
        raise PermissionError("لا توجد صلاحية لقراءة ملف الإعدادات.") from exc
    if not isinstance(loaded, dict):
        raise ConfigurationError("يجب أن يكون محتوى الإعدادات كائناً JSON.")
    config.update(loaded)
    validate_config(config)
    return config


def validate_config(config: Dict[str, Any]) -> None:
    if config.get("output_format") not in {"table", "json", "quiet"}:
        raise ConfigurationError("output_format يجب أن يكون table أو json أو quiet.")
    if not isinstance(config.get("max_file_mb"), (int, float)) or config["max_file_mb"] <= 0:
        raise ConfigurationError("max_file_mb يجب أن يكون رقماً موجباً.")
    if config.get("log_level") not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ConfigurationError("log_level غير معروف.")


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.WARNING),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
