import os

import pandas as pd
from OTXv2 import OTXv2

API_KEY = os.getenv("OTX_API_KEY")

if not API_KEY:
    raise SystemExit("Set OTX_API_KEY before running this script.")

otx = OTXv2(API_KEY)

print("Fetching healthcare threat pulses and extracting indicators of compromise...")

pulses = otx.search_pulses("Healthcare")["results"]
extracted_iocs = []

for pulse in pulses[:30]:
    pulse_id = pulse.get("id")
    pulse_name = pulse.get("name")

    try:
        full_pulse = otx.get_pulse_details(pulse_id)
        indicators = full_pulse.get("indicators", [])

        for indicator in indicators:
            indicator_type = indicator.get("type")
            indicator_value = indicator.get("indicator")

            if indicator_type in ["IPv4", "domain", "hostname", "URL", "FileHash-SHA256"]:
                extracted_iocs.append(
                    {
                        "threat_name": pulse_name,
                        "indicator_value": indicator_value,
                        "type": indicator_type,
                        "created": indicator.get("created"),
                    }
                )
    except Exception:
        continue

df = pd.DataFrame(extracted_iocs)

if not df.empty:
    df.to_csv("healthcare_iocs.csv", index=False)
    print(f"Saved {len(df)} indicators to healthcare_iocs.csv")
    print(df[["threat_name", "indicator_value", "type"]].head(10))
else:
    print("No indicators were returned for the current query.")
