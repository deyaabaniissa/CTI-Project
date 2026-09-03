import asyncio
from cti.intelligence import _is_known_benign, ThreatIntelligenceService

# 1) allowlist check (no network needed)
cases = [
    ("8.8.8.8", "ipv4"), ("4.2.2.2", "ipv4"), ("1.1.1.1", "ipv4"),
    ("android.googleapis.com", "domain"), ("www.google.com", "domain"),
    ("time.nist.gov", "domain"),
    ("evil-c2-server.ru", "domain"),  # should NOT be in allowlist
]
print("== allowlist check ==")
for value, kind in cases:
    print(f"{value:30s} known_benign={_is_known_benign(value, kind)}")
