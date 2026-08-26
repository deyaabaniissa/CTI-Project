# =====================================================================
# 7) LIVE THREAT-INTELLIGENCE ENRICHMENT FOR CATBOOST
# Run after cells 1 (preparation) and 2 (CatBoost).
#
# Required Kaggle Secrets:
#   OTX_API_KEY, VT_API_KEY
# Optional but recommended:
#   NVD_API_KEY
# OSV does not require an API key.
# =====================================================================

import base64
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import numpy as np
import pandas as pd
import requests

try:
    from kaggle_secrets import UserSecretsClient
except Exception:
    UserSecretsClient = None


CTI_CACHE_PATH = "/kaggle/working/live_threat_intel_cache.sqlite3"
CTI_RESULTS_PATH = "/kaggle/working/live_investigation_results.jsonl"
CTI_CACHE_HOURS = 24
HTTP_TIMEOUT_SECONDS = 20


def get_secret(name):
    """Read an API key without printing or storing it in notebook output."""
    value = os.getenv(name)
    if value:
        return value
    if UserSecretsClient is None:
        return None
    try:
        return UserSecretsClient().get_secret(name)
    except Exception:
        return None


OTX_API_KEY = get_secret("OTX_API_KEY")
VT_API_KEY = get_secret("VT_API_KEY")
NVD_API_KEY = get_secret("NVD_API_KEY")


def secret_status():
    status = {
        "OTX_API_KEY": bool(OTX_API_KEY),
        "VT_API_KEY": bool(VT_API_KEY),
        "NVD_API_KEY": bool(NVD_API_KEY),
        "OSV_API_KEY": "not required",
    }
    print("Live threat-intelligence configuration:")
    display(pd.DataFrame([status]))
    if not OTX_API_KEY:
        print("Add OTX_API_KEY in Add-ons -> Secrets for live OTX lookup.")
    if not VT_API_KEY:
        print("Add VT_API_KEY in Add-ons -> Secrets for live VirusTotal lookup.")
    if not NVD_API_KEY:
        print("NVD can still run, but its unauthenticated rate limit is lower.")
    return status


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def init_cti_cache():
    with sqlite3.connect(CTI_CACHE_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cti_cache (
                source TEXT NOT NULL,
                query_type TEXT NOT NULL,
                query_value TEXT NOT NULL,
                fetched_at REAL NOT NULL,
                response_json TEXT NOT NULL,
                PRIMARY KEY (source, query_type, query_value)
            )
            """
        )
        connection.commit()


def cache_get(source, query_type, query_value, max_age_hours=CTI_CACHE_HOURS):
    with sqlite3.connect(CTI_CACHE_PATH) as connection:
        row = connection.execute(
            """
            SELECT fetched_at, response_json
            FROM cti_cache
            WHERE source = ? AND query_type = ? AND query_value = ?
            """,
            (source, query_type, query_value),
        ).fetchone()
    if row is None:
        return None
    fetched_at, response_json = row
    if time.time() - fetched_at > max_age_hours * 3600:
        return None
    return json.loads(response_json)


def cache_put(source, query_type, query_value, response):
    with sqlite3.connect(CTI_CACHE_PATH) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO cti_cache
            (source, query_type, query_value, fetched_at, response_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                source,
                query_type,
                query_value,
                time.time(),
                json.dumps(response, ensure_ascii=False, default=str),
            ),
        )
        connection.commit()


def cached_live_request(
    source,
    query_type,
    query_value,
    method,
    url,
    *,
    headers=None,
    params=None,
    payload=None,
    force_refresh=False,
):
    """Local database first; live API only on cache miss or expiration."""
    normalized_value = str(query_value).strip()
    if not force_refresh:
        cached = cache_get(source, query_type, normalized_value)
        if cached is not None:
            return {
                "source": source,
                "query_type": query_type,
                "query_value": normalized_value,
                "lookup_mode": "local_cache",
                "ok": True,
                "data": cached,
            }

    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=payload,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        if response.status_code == 404:
            body = {"not_found": True}
        else:
            response.raise_for_status()
            body = response.json()
        cache_put(source, query_type, normalized_value, body)
        return {
            "source": source,
            "query_type": query_type,
            "query_value": normalized_value,
            "lookup_mode": "live_api",
            "ok": True,
            "http_status": response.status_code,
            "data": body,
        }
    except Exception as error:
        return {
            "source": source,
            "query_type": query_type,
            "query_value": normalized_value,
            "lookup_mode": "live_api",
            "ok": False,
            "error": f"{type(error).__name__}: {error}",
        }


def clean_value(value):
    if value is None:
        return None
    if isinstance(value, float) and np.isnan(value):
        return None
    value = str(value).strip()
    return value or None


def detect_hash_type(value):
    value = clean_value(value)
    if not value or not re.fullmatch(r"[A-Fa-f0-9]+", value):
        return None
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value))


def extract_observables(event):
    """Keep raw identifiers; the 12 numeric model features are not IOCs."""
    observables = {
        "ips": set(),
        "domains": set(),
        "urls": set(),
        "hashes": set(),
        "cves": set(),
        "packages": [],
        "products": [],
    }

    for key in ("ip", "src_ip", "dst_ip", "source_ip", "destination_ip"):
        value = clean_value(event.get(key))
        if value:
            try:
                ipaddress.ip_address(value)
                observables["ips"].add(value)
            except ValueError:
                pass

    for key in ("domain", "hostname"):
        value = clean_value(event.get(key))
        if value:
            observables["domains"].add(value.lower())

    for key in ("url", "uri"):
        value = clean_value(event.get(key))
        if value:
            observables["urls"].add(value)

    for key in ("hash", "md5", "sha1", "sha256", "file_hash"):
        value = clean_value(event.get(key))
        if value and detect_hash_type(value):
            observables["hashes"].add(value.lower())

    for key in ("cve", "cve_id"):
        value = clean_value(event.get(key))
        if value:
            for cve in re.findall(r"CVE-\d{4}-\d{4,}", value.upper()):
                observables["cves"].add(cve)

    package_name = clean_value(event.get("package") or event.get("package_name"))
    package_version = clean_value(
        event.get("package_version") or event.get("version")
    )
    ecosystem = clean_value(event.get("ecosystem"))
    if package_name and ecosystem:
        observables["packages"].append(
            {
                "name": package_name,
                "ecosystem": ecosystem,
                "version": package_version,
            }
        )

    vendor = clean_value(event.get("vendor"))
    product = clean_value(event.get("product"))
    product_version = clean_value(event.get("product_version"))
    cpe = clean_value(event.get("cpe"))
    if cpe or product:
        observables["products"].append(
            {
                "vendor": vendor,
                "product": product,
                "version": product_version,
                "cpe": cpe,
            }
        )

    return {
        key: sorted(value) if isinstance(value, set) else value
        for key, value in observables.items()
    }


def otx_lookup(indicator_type, indicator, force_refresh=False):
    if not OTX_API_KEY:
        return {
            "source": "OTX",
            "ok": False,
            "skipped": True,
            "error": "Missing Kaggle Secret: OTX_API_KEY",
        }
    otx_type = {
        "ip": "IPv6" if ":" in indicator else "IPv4",
        "domain": "domain",
        "url": "url",
        "md5": "FileHash-MD5",
        "sha1": "FileHash-SHA1",
        "sha256": "FileHash-SHA256",
    }[indicator_type]
    url = (
        "https://otx.alienvault.com/api/v1/indicators/"
        f"{otx_type}/{quote(indicator, safe='')}/general"
    )
    return cached_live_request(
        "OTX",
        indicator_type,
        indicator,
        "GET",
        url,
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        force_refresh=force_refresh,
    )


def virustotal_lookup(indicator_type, indicator, force_refresh=False):
    if not VT_API_KEY:
        return {
            "source": "VirusTotal",
            "ok": False,
            "skipped": True,
            "error": "Missing Kaggle Secret: VT_API_KEY",
        }
    if indicator_type == "ip":
        path = f"ip_addresses/{quote(indicator, safe='')}"
    elif indicator_type == "domain":
        path = f"domains/{quote(indicator, safe='')}"
    elif indicator_type == "url":
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        path = f"urls/{url_id}"
    else:
        path = f"files/{quote(indicator, safe='')}"
    return cached_live_request(
        "VirusTotal",
        indicator_type,
        indicator,
        "GET",
        f"https://www.virustotal.com/api/v3/{path}",
        headers={"x-apikey": VT_API_KEY},
        force_refresh=force_refresh,
    )


def nvd_lookup_cve(cve_id, force_refresh=False):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    return cached_live_request(
        "NVD",
        "cve",
        cve_id,
        "GET",
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        headers=headers,
        params={"cveIds": cve_id},
        force_refresh=force_refresh,
    )


def nvd_lookup_product(product_record, force_refresh=False):
    cpe = product_record.get("cpe")
    if cpe:
        params = {"cpeName": cpe}
        query_value = cpe
        query_type = "cpe"
    else:
        parts = [
            product_record.get("vendor"),
            product_record.get("product"),
            product_record.get("version"),
        ]
        query_value = " ".join(part for part in parts if part)
        params = {"keywordSearch": query_value}
        query_type = "product"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    return cached_live_request(
        "NVD",
        query_type,
        query_value,
        "GET",
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        headers=headers,
        params=params,
        force_refresh=force_refresh,
    )


def osv_lookup(package_record, force_refresh=False):
    payload = {
        "package": {
            "name": package_record["name"],
            "ecosystem": package_record["ecosystem"],
        }
    }
    if package_record.get("version"):
        payload["version"] = package_record["version"]
    query_value = (
        f"{package_record['ecosystem']}:{package_record['name']}:"
        f"{package_record.get('version') or '*'}"
    )
    return cached_live_request(
        "OSV",
        "package",
        query_value,
        "POST",
        "https://api.osv.dev/v1/query",
        payload=payload,
        force_refresh=force_refresh,
    )


def run_live_cti_queries(observables, force_refresh=False):
    results = []

    for ip in observables["ips"]:
        results.append(otx_lookup("ip", ip, force_refresh))
        results.append(virustotal_lookup("ip", ip, force_refresh))

    for domain in observables["domains"]:
        results.append(otx_lookup("domain", domain, force_refresh))
        results.append(virustotal_lookup("domain", domain, force_refresh))

    for url in observables["urls"]:
        results.append(otx_lookup("url", url, force_refresh))
        results.append(virustotal_lookup("url", url, force_refresh))

    for file_hash in observables["hashes"]:
        hash_type = detect_hash_type(file_hash)
        results.append(otx_lookup(hash_type, file_hash, force_refresh))
        results.append(virustotal_lookup(hash_type, file_hash, force_refresh))

    for cve_id in observables["cves"]:
        results.append(nvd_lookup_cve(cve_id, force_refresh))

    for product_record in observables["products"]:
        results.append(nvd_lookup_product(product_record, force_refresh))

    for package_record in observables["packages"]:
        results.append(osv_lookup(package_record, force_refresh))

    return results


def summarize_otx(data):
    pulse_info = data.get("pulse_info", {}) if isinstance(data, dict) else {}
    pulse_count = int(pulse_info.get("count", 0) or 0)
    return {
        "pulse_count": pulse_count,
        "score": min(1.0, pulse_count / 5.0),
    }


def summarize_virustotal(data):
    attributes = (data.get("data") or {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(value or 0) for value in stats.values())
    score = (malicious + 0.5 * suspicious) / total if total else 0.0
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "total_engines": total,
        "score": float(min(1.0, score)),
    }


def extract_cvss(cve):
    metrics = cve.get("metrics", {}) or {}
    scores = []
    for key in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        for metric in metrics.get(key, []) or []:
            score = (metric.get("cvssData") or {}).get("baseScore")
            if score is not None:
                scores.append(float(score))
    return max(scores, default=0.0)


def summarize_nvd(data):
    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    cvss_scores = []
    kev = False
    cve_ids = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_ids.append(cve.get("id"))
        cvss_scores.append(extract_cvss(cve))
        kev = kev or bool(cve.get("cisaExploitAdd"))
    maximum_cvss = max(cvss_scores, default=0.0)
    score = maximum_cvss / 10.0
    if kev:
        score = max(score, 0.95)
    return {
        "cve_count": len(vulnerabilities),
        "cve_ids": [value for value in cve_ids if value][:20],
        "maximum_cvss": maximum_cvss,
        "known_exploited": kev,
        "score": float(min(1.0, score)),
    }


def summarize_osv(data):
    vulnerabilities = data.get("vulns", []) if isinstance(data, dict) else []
    ids = [item.get("id") for item in vulnerabilities if item.get("id")]
    return {
        "vulnerability_count": len(vulnerabilities),
        "vulnerability_ids": ids[:20],
        "score": min(1.0, len(vulnerabilities) / 3.0),
    }


def summarize_cti_results(results):
    summaries = []
    for result in results:
        if not result.get("ok"):
            summaries.append(
                {
                    "source": result.get("source"),
                    "query_type": result.get("query_type"),
                    "query_value": result.get("query_value"),
                    "ok": False,
                    "error": result.get("error"),
                    "score": 0.0,
                }
            )
            continue

        source = result["source"]
        data = result.get("data", {})
        if source == "OTX":
            summary = summarize_otx(data)
        elif source == "VirusTotal":
            summary = summarize_virustotal(data)
        elif source == "NVD":
            summary = summarize_nvd(data)
        elif source == "OSV":
            summary = summarize_osv(data)
        else:
            summary = {"score": 0.0}
        summaries.append(
            {
                "source": source,
                "query_type": result.get("query_type"),
                "query_value": result.get("query_value"),
                "lookup_mode": result.get("lookup_mode"),
                "ok": True,
                **summary,
            }
        )
    return summaries


def predict_catboost_event(event):
    missing = [feature for feature in selected_features if feature not in event]
    if missing:
        raise ValueError(
            "The event is missing CatBoost features: " + ", ".join(missing)
        )
    row = pd.DataFrame(
        [{feature: pd.to_numeric(event[feature], errors="coerce")
          for feature in selected_features}]
    ).replace([np.inf, -np.inf], np.nan).fillna(0.0)
    prediction_encoded = int(np.asarray(catboost_model.predict(row)).reshape(-1)[0])
    probabilities = np.asarray(catboost_model.predict_proba(row))[0]
    predicted_family = label_encoder.inverse_transform([prediction_encoded])[0]
    confidence = float(np.max(probabilities))
    probability_by_family = {
        family: float(probability)
        for family, probability in zip(label_encoder.classes_, probabilities)
    }
    return {
        "predicted_family": predicted_family,
        "confidence": confidence,
        "probabilities": probability_by_family,
    }


def recommended_actions(prediction, cti_summaries, risk_score):
    actions = []
    family = prediction["predicted_family"]
    if risk_score >= 80:
        actions.append("Immediately isolate the affected hospital endpoint or VLAN.")
    elif risk_score >= 60:
        actions.append("Restrict the endpoint and start priority incident triage.")

    malicious_ioc = any(
        item.get("source") in {"OTX", "VirusTotal"}
        and float(item.get("score", 0)) >= 0.20
        for item in cti_summaries
    )
    if malicious_ioc:
        actions.append("Block confirmed malicious IP/domain/hash in firewall, DNS and EDR.")

    vulnerable_asset = any(
        item.get("source") in {"NVD", "OSV"}
        and float(item.get("score", 0)) >= 0.70
        for item in cti_summaries
    )
    if vulnerable_asset:
        actions.append("Patch or mitigate the affected product/package and verify its version.")

    if family in {"DDoS", "DoS"}:
        actions.append("Apply rate limiting and upstream DDoS/DoS filtering.")
    elif family == "Spoofing":
        actions.append("Inspect ARP tables, enable DHCP snooping and dynamic ARP inspection.")
    elif family == "Recon":
        actions.append("Block the scanner and review exposed services and authentication logs.")
    elif family == "MQTT":
        actions.append("Restrict MQTT broker access, rotate credentials and enforce TLS/ACLs.")

    actions.append("Preserve the original event and enrichment JSON for analyst review.")
    return list(dict.fromkeys(actions))


def investigate_event_live(event, force_refresh=False):
    """
    Full runtime flow:
      CatBoost prediction -> local CTI DB -> live APIs -> risk -> actions.
    Each API is called only when the event contains its required identifier.
    """
    prediction = predict_catboost_event(event)
    observables = extract_observables(event)
    raw_results = run_live_cti_queries(observables, force_refresh=force_refresh)
    cti_summaries = summarize_cti_results(raw_results)

    successful_scores = [
        float(item.get("score", 0.0))
        for item in cti_summaries
        if item.get("ok")
    ]
    cti_score = max(successful_scores, default=0.0)
    family = prediction["predicted_family"]
    model_attack_score = (
        prediction["confidence"]
        if family != "Benign"
        else 1.0 - prediction["confidence"]
    )
    asset_criticality = float(event.get("asset_criticality", 0.8))
    asset_criticality = float(np.clip(asset_criticality, 0.0, 1.0))
    risk_score = round(
        100
        * (
            0.60 * model_attack_score
            + 0.25 * cti_score
            + 0.15 * asset_criticality
        ),
        2,
    )

    investigation = {
        "investigation_id": hashlib.sha256(
            f"{utc_now_iso()}:{json.dumps(event, sort_keys=True, default=str)}".encode()
        ).hexdigest()[:16],
        "created_at": utc_now_iso(),
        "model": "official_ciciomt2024_catboost_12_features",
        "prediction": prediction,
        "observables": observables,
        "cti_summary": cti_summaries,
        "risk_score": risk_score,
        "risk_level": (
            "critical" if risk_score >= 80
            else "high" if risk_score >= 60
            else "medium" if risk_score >= 40
            else "low"
        ),
    }
    investigation["recommended_actions"] = recommended_actions(
        prediction,
        cti_summaries,
        risk_score,
    )

    with open(CTI_RESULTS_PATH, "a", encoding="utf-8") as output_file:
        output_file.write(
            json.dumps(investigation, ensure_ascii=False, default=str) + "\n"
        )

    print("\nLIVE INCIDENT INVESTIGATION")
    print("Prediction :", prediction["predicted_family"])
    print("Confidence :", f"{prediction['confidence']:.4f}")
    print("Risk score :", risk_score)
    print("Risk level :", investigation["risk_level"])
    if cti_summaries:
        display(pd.DataFrame(cti_summaries))
    else:
        print("No IOC/CVE/package identifiers were present for live enrichment.")
    print("\nRecommended actions:")
    for action in investigation["recommended_actions"]:
        print("-", action)
    return investigation


init_cti_cache()
secret_status()
print("\nReady: call investigate_event_live(event_dict).")

