"""License_Scanner — 零成本合規授權掃描器。

掃描所有已安裝 Python 套件的授權條款，比對允許清單。發現非允許授權時
記錄違規並發出 compliance_violation 事件，並產生 JSON 格式合規報告。

授權資訊來源預設用 importlib.metadata，但可注入 lookup 函式以便測試。
"""
from __future__ import annotations

import json
import re
from typing import Callable, Iterable

import structlog

from .event_bus import EventBus
from .models import Event, PackageLicense

logger = structlog.get_logger(__name__)

TOPIC_COMPLIANCE_VIOLATION = "compliance.violation"

# 允許的授權清單（零成本約束）
ALLOWED_LICENSES: set[str] = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "PSF",
    "LGPL-2.1",
    "LGPL-3.0",
    "MPL-2.0",
}

# 常見授權字串正規化對照（classifier / 自由文字 → SPDX-like）
_NORMALIZE: dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "apache": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "psf": "PSF",
    "python software foundation license": "PSF",
    "lgpl-2.1": "LGPL-2.1",
    "lgpl-3.0": "LGPL-3.0",
    "gnu lesser general public license v2": "LGPL-2.1",
    "gnu lesser general public license v3": "LGPL-3.0",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
}

# 授權查詢函式：套件名 → (version, raw_license)
LicenseLookup = Callable[[str], tuple[str, str]]


def normalize_license(raw: str) -> str:
    """將自由文字授權字串正規化為 SPDX-like 識別碼。無法辨識則回原字串去空白。"""
    if not raw:
        return "UNKNOWN"
    key = raw.strip().lower()
    if key in _NORMALIZE:
        return _NORMALIZE[key]
    # 嘗試從 classifier 片段抽取（如 "License :: OSI Approved :: MIT License"）
    tail = key.split("::")[-1].strip()
    if tail in _NORMALIZE:
        return _NORMALIZE[tail]
    # 直接命中允許清單（大小寫不敏感）
    for allowed in ALLOWED_LICENSES:
        if key == allowed.lower() or tail == allowed.lower():
            return allowed
    return raw.strip()


def _metadata_lookup(name: str) -> tuple[str, str]:
    """預設以 importlib.metadata 取得套件版本與授權。"""
    from importlib import metadata

    try:
        md = metadata.metadata(name)
    except metadata.PackageNotFoundError:
        return "unknown", "UNKNOWN"
    version = md.get("Version", "unknown")
    # 優先 License 欄位，否則從 classifiers 找
    lic = md.get("License") or ""
    if not lic or lic.strip().lower() in ("", "unknown"):
        for c in md.get_all("Classifier") or []:
            if c.startswith("License ::"):
                lic = c
                break
    return version, lic or "UNKNOWN"


class LicenseScanner:
    """授權合規掃描器。"""

    def __init__(
        self,
        event_bus: EventBus | None = None,
        lookup: LicenseLookup | None = None,
        allowed: set[str] | None = None,
    ) -> None:
        self._bus = event_bus
        self._lookup = lookup or _metadata_lookup
        self._allowed = allowed or ALLOWED_LICENSES
        self.violations: list[PackageLicense] = []

    def scan_package(self, name: str) -> PackageLicense:
        version, raw = self._lookup(name)
        normalized = normalize_license(raw)
        compliant = normalized in self._allowed
        return PackageLicense(
            name=name, version=version, license=normalized, compliant=compliant,
        )

    async def scan_all(self, packages: Iterable[str]) -> list[PackageLicense]:
        results: list[PackageLicense] = []
        self.violations = []
        for name in packages:
            pkg = self.scan_package(name)
            results.append(pkg)
            if not pkg.compliant:
                self.violations.append(pkg)
                await self._emit_violation(pkg)
        return results

    async def _emit_violation(self, pkg: PackageLicense) -> None:
        logger.warning("compliance_violation", package=pkg.name,
                       license=pkg.license, version=pkg.version)
        if self._bus is not None:
            await self._bus.publish_and_wait(Event(
                topic=TOPIC_COMPLIANCE_VIOLATION,
                source="license_scanner",
                payload={"package": pkg.name, "version": pkg.version,
                         "license": pkg.license},
            ))

    @staticmethod
    def generate_report(results: list[PackageLicense]) -> str:
        """產生 JSON 格式合規報告，列出所有套件名稱、版本、授權與合規狀態。"""
        report = {
            "total": len(results),
            "compliant": sum(1 for r in results if r.compliant),
            "violations": sum(1 for r in results if not r.compliant),
            "packages": [
                {
                    "name": r.name,
                    "version": r.version,
                    "license": r.license,
                    "compliant": r.compliant,
                }
                for r in results
            ],
        }
        return json.dumps(report, ensure_ascii=False, indent=2)
