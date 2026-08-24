# =====================================================================
# 8) RUN ONE LIVE INVESTIGATION
# Replace the example identifiers with identifiers from the hospital log.
# This example intentionally includes fields needed by all four sources.
# =====================================================================

# Use one network-flow row only to demonstrate the CatBoost input.
# In production, replace this with the 12 features extracted from the
# incoming hospital network event.
live_event = {
    feature: float(X_test.iloc[0][feature])
    for feature in selected_features
}

# Threat-intelligence identifiers from the ORIGINAL event/asset inventory.
# Never invent these values for a real alert.
live_event.update({
    "src_ip": "8.8.8.8",                    # OTX + VirusTotal
    "domain": "example.com",                # OTX + VirusTotal
    "cve_id": "CVE-2021-44228",             # NVD
    "package_name": "org.apache.logging.log4j:log4j-core",  # OSV
    "ecosystem": "Maven",                   # OSV
    "package_version": "2.14.1",            # OSV
    "vendor": "Apache",                     # NVD product lookup
    "product": "Log4j",                     # NVD product lookup
    "product_version": "2.14.1",
    "asset_criticality": 0.90,
})

# False = use the local threat-intelligence database first.
# Set True only when you explicitly want to bypass the 24-hour cache.
live_result = investigate_event_live(
    live_event,
    force_refresh=False,
)

print("\nFull live result saved to:", CTI_RESULTS_PATH)

