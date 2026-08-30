from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from dotenv import load_dotenv

from cti.indicators import CVE_PATTERN, classify_indicator, is_public_indicator


OSV_API_BASE = "https://api.osv.dev/v1"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OTX_API_BASE = "https://otx.alienvault.com/api/v1"
VT_API_BASE = "https://www.virustotal.com/api/v3"


class IntelligenceRequestError(RuntimeError):
    """Structured provider error safe to expose in an analyst report."""

    def __init__(
        self,
        message: str,
        *,
        error_type: str,
        http_status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.http_status = http_status


def _error_payload(error: Exception) -> dict[str, Any]:
    return {
        "available": False,
        "found": False,
        "error": str(error)[:500],
        "error_type": str(getattr(error, "error_type", "provider_error")),
        "http_status": getattr(error, "http_status", None),
    }

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    request_headers = {"Accept": "application/json", "User-Agent": "healthcare-cti-soc/2.0"}
    request_headers.update(headers or {})
    encoded_body = None
    if body is not None:
        encoded_body = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = Request(url, data=encoded_body, headers=request_headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else {}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise IntelligenceRequestError(
            f"HTTP {exc.code}: {detail or exc.reason}",
            error_type="http_error",
            http_status=exc.code,
        ) from exc
    except URLError as exc:
        raise IntelligenceRequestError(
            f"Network error: {exc.reason}",
            error_type="network_error",
        ) from exc
    except TimeoutError as exc:
        raise IntelligenceRequestError(
            "Network timeout while waiting for the provider.",
            error_type="timeout",
        ) from exc
    except json.JSONDecodeError as exc:
        raise IntelligenceRequestError(
            "Provider returned a response that was not valid JSON.",
            error_type="invalid_json",
        ) from exc


async def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    for attempt in range(3):
        try:
            return await asyncio.to_thread(
                _request_json,
                method,
                url,
                headers=headers,
                body=body,
                timeout=timeout,
            )
        except IntelligenceRequestError as exc:
            retryable = exc.error_type in {"network_error", "timeout"} or (
                exc.http_status == 429 or bool(exc.http_status and exc.http_status >= 500)
            )
            if not retryable or attempt == 2:
                raise
            await asyncio.sleep(0.75 * (2**attempt))
    raise AssertionError("Unreachable retry state")


class ThreatIntelligenceService:
    """Live, cached access to OSV, NVD, AlienVault OTX, and VirusTotal."""

    def __init__(self, project_root: Path):
        self.project_root = project_root.resolve()
        load_dotenv(self.project_root / ".env")
        self.otx_api_key = os.getenv("OTX_API_KEY", "").strip()
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.nvd_api_key = os.getenv("NVD_API_KEY", "").strip()
        self.cache_ttl = max(60, int(os.getenv("INTEL_CACHE_TTL_SECONDS", "900")))
        self.scan_timeout = max(30, int(os.getenv("OSV_SCAN_TIMEOUT_SECONDS", "180")))
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        # Coalesce identical requests.  This prevents a static replay or many
        # dashboard clients from consuming an API quota for the same IoC.
        self._indicator_locks: dict[str, asyncio.Lock] = {}
        self._refresh_lock = asyncio.Lock()
        self._posture: dict[str, Any] = {
            "state": "pending",
            "last_updated": None,
            "packages_scanned": 0,
            "vulnerability_count": 0,
            "cve_count": 0,
            "critical_count": 0,
            "known_exploited_count": 0,
            "max_cvss": 0.0,
            "vulnerabilities": [],
            "message": "The first dependency scan has not completed.",
        }
        self._states: dict[str, dict[str, Any]] = {
            "osv": self._new_state("OSV", True, "dependency vulnerabilities"),
            "nvd": self._new_state("NVD", True, "CVE severity and exploitation metadata"),
            "otx": self._new_state("AlienVault OTX", bool(self.otx_api_key), "community IoC reputation"),
            "virustotal": self._new_state(
                "VirusTotal", bool(self.vt_api_key), "multi-engine IoC reputation"
            ),
        }

    @staticmethod
    def _new_state(name: str, configured: bool, capability: str) -> dict[str, Any]:
        return {
            "name": name,
            "configured": configured,
            "status": "ready" if configured else "needs_key",
            "capability": capability,
            "last_success": None,
            "last_error": None,
            "latency_ms": None,
        }

    def _record(self, source: str, started: float, error: Exception | None = None) -> None:
        state = self._states[source]
        state["latency_ms"] = round((time.perf_counter() - started) * 1000)
        if error is None:
            state["status"] = "live"
            state["last_success"] = utc_now()
            state["last_error"] = None
        else:
            state["status"] = "error"
            state["last_error"] = str(error)[:300]

    def status(self) -> dict[str, Any]:
        return {
            "sources": self._states,
            "cache_entries": len(self._cache),
            "cache_ttl_seconds": self.cache_ttl,
            "posture_last_updated": self._posture.get("last_updated"),
        }

    def posture(self) -> dict[str, Any]:
        return self._posture

    async def enrich_indicator(
        self, raw_indicator: str, *, force_refresh: bool = False
    ) -> dict[str, Any]:
        indicator, indicator_type = classify_indicator(raw_indicator)
        if not is_public_indicator(indicator, indicator_type):
            applicable_sources = (
                ["nvd", "osv"] if indicator_type in {"cve", "ghsa"} else ["otx", "virustotal"]
            )
            return {
                "indicator": indicator,
                "type": indicator_type,
                "verdict": "private",
                "confidence": 0.0,
                "sources": {},
                "coverage": {
                    "applicable_sources": applicable_sources,
                    "configured_sources": [],
                    "available_sources": [],
                    "queried_sources": [],
                    "complete": True,
                },
                "message": "Private or local indicators are not sent to external services.",
                "cached": False,
            }

        cache_key = f"{indicator_type}:{indicator}"
        cached = self._cache.get(cache_key)
        if not force_refresh and cached and cached[0] > time.time():
            return {**cached[1], "cached": True}

        lock = self._indicator_locks.setdefault(cache_key, asyncio.Lock())
        async with lock:
            # A simultaneous caller can have populated the cache while this
            # request waited for the per-indicator lock.
            cached = self._cache.get(cache_key)
            if not force_refresh and cached and cached[0] > time.time():
                return {**cached[1], "cached": True}
            result = await self._enrich_uncached(indicator, indicator_type)
            self._cache[cache_key] = (time.time() + self.cache_ttl, result)
            return result

    async def enrich_package(
        self,
        package_identifier: str,
        *,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """Query OSV for a package/PURL and enrich returned CVEs with NVD."""

        identifier = str(package_identifier or "").strip()
        if not identifier:
            raise ValueError("Package identifier is empty.")
        cache_key = f"package:{identifier.lower()}"
        cached = self._cache.get(cache_key)
        if not force_refresh and cached and cached[0] > time.time():
            return {**cached[1], "cached": True}

        lock = self._indicator_locks.setdefault(cache_key, asyncio.Lock())
        async with lock:
            cached = self._cache.get(cache_key)
            if not force_refresh and cached and cached[0] > time.time():
                return {**cached[1], "cached": True}

            started = time.perf_counter()
            try:
                if identifier.lower().startswith("pkg:"):
                    query = {"package": {"purl": identifier}}
                else:
                    parts = identifier.split(":", 2)
                    if len(parts) != 3 or not all(parts):
                        raise ValueError(
                            "Package identifiers must be a PURL or ecosystem:name:version."
                        )
                    ecosystem, name, version = parts
                    query = {
                        "version": version,
                        "package": {"ecosystem": ecosystem, "name": name},
                    }
                response = await request_json(
                    "POST",
                    f"{OSV_API_BASE}/query",
                    body=query,
                    timeout=30,
                )
                vulnerabilities = list(response.get("vulns") or [])
                aliases = list(dict.fromkeys(
                    str(alias).upper()
                    for vulnerability in vulnerabilities
                    for alias in vulnerability.get("aliases") or []
                    if isinstance(alias, str)
                ))
                cve_ids = [alias for alias in aliases if CVE_PATTERN.fullmatch(alias)][:100]
                osv_payload = {
                    "available": True,
                    "found": bool(vulnerabilities),
                    "id": (vulnerabilities[0].get("id") if vulnerabilities else identifier),
                    "aliases": aliases,
                    "summary": (
                        vulnerabilities[0].get("summary")
                        if vulnerabilities
                        else "No OSV vulnerability matched this package."
                    ),
                    "affected_packages": len(vulnerabilities),
                }
                self._record("osv", started)
            except Exception as exc:
                self._record("osv", started, exc)
                osv_payload = _error_payload(exc)
                vulnerabilities = []
                cve_ids = []

            try:
                nvd_records = await self._lookup_nvd(cve_ids) if cve_ids else []
                nvd_payload = {
                    "available": True,
                    "found": bool(nvd_records),
                    "records": nvd_records,
                }
            except Exception as exc:
                nvd_records = []
                nvd_payload = {**_error_payload(exc), "records": []}

            available_sources = [
                source
                for source, payload in {"osv": osv_payload, "nvd": nvd_payload}.items()
                if payload.get("available")
            ]
            found = bool(vulnerabilities or nvd_records)
            result = {
                "indicator": identifier,
                "type": "package",
                "verdict": "vulnerable" if found else ("not_found" if available_sources else "unknown"),
                "confidence": 0.9 if found and len(available_sources) == 2 else (0.65 if found else 0.0),
                "sources": {"osv": osv_payload, "nvd": nvd_payload},
                "coverage": {
                    "applicable_sources": ["osv", "nvd"],
                    "configured_sources": ["osv", "nvd"],
                    "available_sources": available_sources,
                    "queried_sources": ["osv", "nvd"],
                    "complete": len(available_sources) == 2,
                },
                "message": None if found else "The package was not confirmed vulnerable by OSV/NVD.",
                "cached": False,
            }
            self._cache[cache_key] = (time.time() + self.cache_ttl, result)
            return result

    async def _enrich_uncached(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        """Route a normalized reference only to databases that understand it."""

        if indicator_type in {"cve", "ghsa"}:
            return await self._enrich_vulnerability_reference(indicator, indicator_type)
        return await self._enrich_ioc(indicator, indicator_type)

    async def _enrich_ioc(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        """Query OTX and VirusTotal for a public network or file indicator."""

        tasks: dict[str, asyncio.Task] = {}
        if self.otx_api_key:
            tasks["otx"] = asyncio.create_task(self._lookup_otx(indicator, indicator_type))
        if self.vt_api_key:
            tasks["virustotal"] = asyncio.create_task(self._lookup_virustotal(indicator, indicator_type))

        source_results: dict[str, Any] = {}
        if tasks:
            responses = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for source, response in zip(tasks, responses):
                if isinstance(response, Exception):
                    source_results[source] = _error_payload(response)
                else:
                    source_results[source] = response

        otx = source_results.get("otx", {})
        vt = source_results.get("virustotal", {})
        pulse_count = int(otx.get("pulse_count", 0) or 0)
        malicious = int(vt.get("malicious", 0) or 0)
        suspicious = int(vt.get("suspicious", 0) or 0)
        total_engines = max(1, int(vt.get("total_engines", 0) or 0))
        vt_confidence = min(1.0, (malicious + 0.5 * suspicious) / total_engines * 4)
        otx_confidence = min(1.0, pulse_count / 4)
        confidence = round(1 - (1 - 0.75 * otx_confidence) * (1 - 0.9 * vt_confidence), 4)
        malicious_match = pulse_count > 0 or malicious > 0 or suspicious > 1

        configured_sources = [
            source for source in ("otx", "virustotal") if self._states[source]["configured"]
        ]
        available_sources = [
            source for source, payload in source_results.items() if payload.get("available")
        ]
        result = {
            "indicator": indicator,
            "type": indicator_type,
            "verdict": "malicious" if malicious_match else ("clean" if available_sources else "unknown"),
            "confidence": confidence,
            "sources": source_results,
            "coverage": {
                "applicable_sources": ["otx", "virustotal"],
                "configured_sources": configured_sources,
                "available_sources": available_sources,
                "queried_sources": list(source_results),
                "complete": bool(configured_sources) and len(available_sources) == len(configured_sources),
            },
            "message": (
                None
                if available_sources
                else (
                    "No configured IoC provider returned an available result."
                    if configured_sources
                    else "Configure OTX_API_KEY and VIRUSTOTAL_API_KEY for IoC enrichment."
                )
            ),
            "cached": False,
        }
        return result

    async def _enrich_vulnerability_reference(
        self, indicator: str, indicator_type: str
    ) -> dict[str, Any]:
        """Check OSV first and add NVD severity/KEV evidence for matching CVEs."""

        source_results: dict[str, Any] = {}
        try:
            osv = await self._lookup_osv_reference(indicator)
            source_results["osv"] = osv
        except Exception as exc:
            osv = _error_payload(exc)
            source_results["osv"] = osv

        cve_ids: list[str] = []
        if indicator_type == "cve":
            cve_ids.append(indicator)
        if osv.get("found"):
            cve_ids.extend(
                alias.upper()
                for alias in osv.get("aliases", [])
                if isinstance(alias, str) and CVE_PATTERN.fullmatch(alias)
            )
        cve_ids = list(dict.fromkeys(cve_ids))[:100]

        try:
            nvd_records = await self._lookup_nvd(cve_ids) if cve_ids else []
            source_results["nvd"] = {
                "available": True,
                "found": bool(nvd_records),
                "records": nvd_records,
            }
        except Exception as exc:
            nvd_records = []
            source_results["nvd"] = {**_error_payload(exc), "records": []}

        found = bool(osv.get("found") or nvd_records)
        max_cvss = max((float(item.get("cvss", 0.0) or 0.0) for item in nvd_records), default=0.0)
        known_exploited = any(bool(item.get("known_exploited")) for item in nvd_records)
        confidence = 0.0
        if found:
            confidence = max(0.55, min(0.95, 0.5 + 0.35 * (max_cvss / 10.0) + (0.1 if known_exploited else 0.0)))

        available_sources = [
            source for source, payload in source_results.items() if payload.get("available")
        ]
        return {
            "indicator": indicator,
            "type": indicator_type,
            "verdict": "vulnerable" if found else ("not_found" if available_sources else "unknown"),
            "confidence": round(confidence, 4),
            "sources": source_results,
            "coverage": {
                "applicable_sources": ["osv", "nvd"],
                "configured_sources": ["osv", "nvd"],
                "available_sources": available_sources,
                "queried_sources": list(source_results),
                "complete": len(available_sources) == 2,
            },
            "message": None if found else "The reference was not confirmed by the available vulnerability databases.",
            "cached": False,
        }

    async def _lookup_osv_reference(self, vulnerability_id: str) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            payload = await request_json(
                "GET", f"{OSV_API_BASE}/vulns/{quote(vulnerability_id, safe='')}", timeout=20
            )
            result = {
                "available": True,
                "found": bool(payload.get("id")),
                "id": payload.get("id"),
                "aliases": payload.get("aliases") or [],
                "summary": payload.get("summary"),
                "affected_packages": len(payload.get("affected") or []),
                "modified": payload.get("modified"),
            }
            self._record("osv", started)
            return result
        except IntelligenceRequestError as exc:
            if str(exc).startswith("HTTP 404:"):
                self._record("osv", started)
                return {
                    "available": True,
                    "found": False,
                    "id": vulnerability_id,
                    "aliases": [],
                }
            self._record("osv", started, exc)
            raise
        except Exception as exc:
            self._record("osv", started, exc)
            raise

    async def _lookup_otx(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        otx_types = {
            "ipv4": "IPv4",
            "ipv6": "IPv6",
            "domain": "domain",
            "url": "url",
            "sha256": "FileHash-SHA256",
            "sha1": "FileHash-SHA1",
            "md5": "FileHash-MD5",
        }
        started = time.perf_counter()
        url = f"{OTX_API_BASE}/indicators/{otx_types[indicator_type]}/{quote(indicator, safe='')}/general"
        try:
            payload = await request_json(
                "GET", url, headers={"X-OTX-API-KEY": self.otx_api_key}, timeout=15
            )
            pulse_info = payload.get("pulse_info") or {}
            result = {
                "available": True,
                "found": True,
                "pulse_count": int(pulse_info.get("count", 0) or 0),
                "reputation": payload.get("reputation", 0) or 0,
                "validation_count": len(payload.get("validation") or []),
            }
            self._record("otx", started)
            return result
        except RuntimeError as exc:
            if str(exc).startswith("HTTP 404:"):
                self._record("otx", started)
                return {
                    "available": True,
                    "found": False,
                    "pulse_count": 0,
                    "reputation": 0,
                    "validation_count": 0,
                }
            self._record("otx", started, exc)
            raise
        except Exception as exc:
            self._record("otx", started, exc)
            raise

    async def _lookup_virustotal(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if indicator_type in {"ipv4", "ipv6"}:
            resource = f"ip_addresses/{quote(indicator, safe='')}"
        elif indicator_type == "domain":
            resource = f"domains/{quote(indicator, safe='')}"
        elif indicator_type == "url":
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            resource = f"urls/{url_id}"
        else:
            resource = f"files/{indicator}"

        started = time.perf_counter()
        try:
            payload = await request_json(
                "GET",
                f"{VT_API_BASE}/{resource}",
                headers={"x-apikey": self.vt_api_key},
                timeout=15,
            )
            attributes = ((payload.get("data") or {}).get("attributes") or {})
            stats = attributes.get("last_analysis_stats") or {}
            total = sum(int(value or 0) for value in stats.values())
            result = {
                "available": True,
                "found": True,
                "malicious": int(stats.get("malicious", 0) or 0),
                "suspicious": int(stats.get("suspicious", 0) or 0),
                "harmless": int(stats.get("harmless", 0) or 0),
                "undetected": int(stats.get("undetected", 0) or 0),
                "total_engines": total,
                "reputation": attributes.get("reputation", 0) or 0,
            }
            self._record("virustotal", started)
            return result
        except RuntimeError as exc:
            if str(exc).startswith("HTTP 404:"):
                self._record("virustotal", started)
                return {
                    "available": True,
                    "found": False,
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "total_engines": 0,
                    "reputation": 0,
                }
            self._record("virustotal", started, exc)
            raise
        except Exception as exc:
            self._record("virustotal", started, exc)
            raise

    async def refresh_posture(self) -> dict[str, Any]:
        if self._refresh_lock.locked():
            return self._posture

        async with self._refresh_lock:
            try:
                scan = await self._scan_osv()
                cve_ids = sorted(
                    {
                        alias
                        for vulnerability in scan["vulnerabilities"]
                        for alias in vulnerability.get("aliases", [])
                        if alias.upper().startswith("CVE-")
                    }
                )
                nvd_records = await self._lookup_nvd(cve_ids[:100]) if cve_ids else []
                by_cve = {item["cve_id"]: item for item in nvd_records}

                enriched_vulnerabilities = []
                for vulnerability in scan["vulnerabilities"]:
                    matching_cves = [
                        by_cve[alias]
                        for alias in vulnerability.get("aliases", [])
                        if alias in by_cve
                    ]
                    max_cvss = max((item["cvss"] for item in matching_cves), default=0.0)
                    known_exploited = any(item["known_exploited"] for item in matching_cves)
                    enriched_vulnerabilities.append(
                        {
                            **vulnerability,
                            "max_cvss": max_cvss,
                            "known_exploited": known_exploited,
                            "nvd": matching_cves,
                        }
                    )

                self._posture = {
                    "state": "ready",
                    "last_updated": utc_now(),
                    "packages_scanned": scan["packages_scanned"],
                    "vulnerability_count": len(enriched_vulnerabilities),
                    "cve_count": len(cve_ids),
                    "critical_count": sum(
                        1 for item in enriched_vulnerabilities if item["max_cvss"] >= 9.0
                    ),
                    "known_exploited_count": sum(
                        1 for item in enriched_vulnerabilities if item["known_exploited"]
                    ),
                    "max_cvss": max(
                        (item["max_cvss"] for item in enriched_vulnerabilities), default=0.0
                    ),
                    "scanner": scan["scanner"],
                    "vulnerabilities": enriched_vulnerabilities[:100],
                    "message": scan.get("message"),
                }
            except Exception as exc:
                self._posture = {
                    **self._posture,
                    "state": "error",
                    "last_updated": utc_now(),
                    "message": str(exc),
                }
            return self._posture

    def _find_scanner(self) -> str | None:
        configured = os.getenv("OSV_SCANNER_PATH", "").strip()
        candidates = [
            configured,
            shutil.which("osv-scanner") or "",
            str(self.project_root / ".tools" / "bin" / "osv-scanner.exe"),
            str(self.project_root / ".tools" / "bin" / "osv-scanner"),
        ]
        return next((candidate for candidate in candidates if candidate and Path(candidate).is_file()), None)

    async def _scan_osv(self) -> dict[str, Any]:
        scanner = self._find_scanner()
        if scanner:
            return await asyncio.to_thread(self._scan_with_cli, scanner)
        return await self._scan_with_api()

    def _scan_with_cli(self, scanner: str) -> dict[str, Any]:
        started = time.perf_counter()
        command = [
            scanner,
            "scan",
            "source",
            "--recursive",
            "--format=json",
            "--verbosity=error",
            "--all-packages",
            str(self.project_root),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.scan_timeout,
                check=False,
            )
            if not completed.stdout.strip():
                raise RuntimeError(
                    f"OSV-Scanner returned no JSON (exit {completed.returncode}): "
                    f"{completed.stderr.strip()[:500]}"
                )
            payload = json.loads(completed.stdout)
            scan = self._normalize_osv_payload(payload)
            scan["scanner"] = "osv-scanner-v2"
            scan["message"] = completed.stderr.strip()[:500] or None
            self._record("osv", started)
            return scan
        except Exception as exc:
            self._record("osv", started, exc)
            raise

    async def _scan_with_api(self) -> dict[str, Any]:
        started = time.perf_counter()
        lockfile = self.project_root / "cti-dashboard" / "package-lock.json"
        if not lockfile.exists():
            error = RuntimeError("No OSV-Scanner executable or supported package-lock.json was found.")
            self._record("osv", started, error)
            raise error

        try:
            payload = json.loads(lockfile.read_text(encoding="utf-8"))
            packages = []
            for path, package in (payload.get("packages") or {}).items():
                name = package.get("name")
                version = package.get("version")
                if path and name and version:
                    packages.append({"name": name, "version": version, "ecosystem": "npm"})

            queries = [
                {
                    "version": package["version"],
                    "package": {"name": package["name"], "ecosystem": "npm"},
                }
                for package in packages
            ]
            response = await request_json(
                "POST", f"{OSV_API_BASE}/querybatch", body={"queries": queries}, timeout=30
            )
            vulnerabilities: list[dict[str, Any]] = []
            seen: set[str] = set()
            for package, result in zip(packages, response.get("results") or []):
                for vulnerability in result.get("vulns") or []:
                    vuln_id = vulnerability.get("id")
                    if not vuln_id or vuln_id in seen:
                        continue
                    seen.add(vuln_id)
                    vulnerabilities.append(
                        {
                            "id": vuln_id,
                            "aliases": vulnerability.get("aliases") or [],
                            "summary": vulnerability.get("summary"),
                            "package": package,
                        }
                    )
            self._record("osv", started)
            return {
                "packages_scanned": len(packages),
                "vulnerabilities": vulnerabilities,
                "scanner": "osv-api-fallback",
                "message": "Install OSV-Scanner v2 for SBOM, lockfile, and recursive source scanning.",
            }
        except Exception as exc:
            self._record("osv", started, exc)
            raise

    @staticmethod
    def _normalize_osv_payload(payload: dict[str, Any]) -> dict[str, Any]:
        packages_scanned = 0
        vulnerabilities: list[dict[str, Any]] = []
        seen: set[str] = set()
        for result in payload.get("results") or []:
            source = result.get("source") or {}
            for package_entry in result.get("packages") or []:
                packages_scanned += 1
                package = package_entry.get("package") or {}
                for vulnerability in package_entry.get("vulnerabilities") or []:
                    vuln_id = vulnerability.get("id")
                    if not vuln_id or vuln_id in seen:
                        continue
                    seen.add(vuln_id)
                    vulnerabilities.append(
                        {
                            "id": vuln_id,
                            "aliases": vulnerability.get("aliases") or [],
                            "summary": vulnerability.get("summary"),
                            "package": {
                                "name": package.get("name"),
                                "version": package.get("version"),
                                "ecosystem": package.get("ecosystem"),
                            },
                            "source": source.get("path"),
                        }
                    )
        return {"packages_scanned": packages_scanned, "vulnerabilities": vulnerabilities}

    async def _lookup_nvd(self, cve_ids: list[str]) -> list[dict[str, Any]]:
        if not cve_ids:
            return []
        started = time.perf_counter()
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        try:
            records = []
            # NVD API 2.0 accepts the singular `cveId` parameter.  Sending the
            # former `cveIds` value silently produced empty/error responses.
            for cve_id in dict.fromkeys(cve_ids):
                query = urlencode({"cveId": cve_id})
                payload = await request_json(
                    "GET", f"{NVD_API_BASE}?{query}", headers=headers, timeout=30
                )
                for entry in payload.get("vulnerabilities") or []:
                    cve = entry.get("cve") or {}
                    metrics = cve.get("metrics") or {}
                    score = 0.0
                    severity = "UNKNOWN"
                    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        candidates = metrics.get(key) or []
                        if candidates:
                            cvss_data = candidates[0].get("cvssData") or {}
                            score = float(cvss_data.get("baseScore", 0.0) or 0.0)
                            severity = cvss_data.get("baseSeverity") or candidates[0].get(
                                "baseSeverity", "UNKNOWN"
                            )
                            break
                    records.append(
                        {
                            "cve_id": cve.get("id"),
                            "cvss": score,
                            "severity": severity,
                            "known_exploited": bool(cve.get("cisaExploitAdd")),
                            "cisa_due_date": cve.get("cisaActionDue"),
                            "required_action": cve.get("cisaRequiredAction"),
                        }
                    )
            self._record("nvd", started)
            return records
        except Exception as exc:
            self._record("nvd", started, exc)
            raise
