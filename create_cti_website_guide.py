"""Generate the Healthcare CTI SOC website guide PDF."""

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "output" / "pdf" / "healthcare_cti_soc_website_guide.pdf"

NAVY = colors.HexColor("#0d161c")
TEAL = colors.HexColor("#54d4c8")
MINT = colors.HexColor("#dff8f3")
INK = colors.HexColor("#16242d")
MUTED = colors.HexColor("#526673")
LINE = colors.HexColor("#c9d9df")
RED = colors.HexColor("#b63e58")
AMBER = colors.HexColor("#a57118")


def header_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(1.55 * cm, 1.35 * cm, A4[0] - 1.55 * cm, 1.35 * cm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(1.55 * cm, 0.88 * cm, "Healthcare CTI SOC - Website workflow guide")
    canvas.drawRightString(A4[0] - 1.55 * cm, 0.88 * cm, f"Page {doc.page}")
    canvas.restoreState()


def paragraph(text, style):
    return Paragraph(text, style)


def numbered_step(number, title, body, styles):
    return KeepTogether(
        [
            Table(
                [[paragraph(f"{int(number):02d}", styles["stepnum"]), paragraph(f"<b>{title}</b><br/>{body}", styles["body"]) ]],
                colWidths=[0.85 * cm, 15.4 * cm],
                style=TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("BACKGROUND", (0, 0), (0, 0), TEAL),
                        ("BOX", (0, 0), (0, 0), 0.4, TEAL),
                        ("BOX", (1, 0), (1, 0), 0.4, LINE),
                        ("LEFTPADDING", (1, 0), (1, 0), 9),
                        ("RIGHTPADDING", (1, 0), (1, 0), 9),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ]
                ),
            ),
            Spacer(1, 7),
        ]
    )


def section(title, intro, styles):
    return [Paragraph(title, styles["h1"]), Paragraph(intro, styles["body"]), Spacer(1, 10)]


def data_table(headers, rows, widths, styles):
    data = [[paragraph(f"<b>{item}</b>", styles["tablehead"]) for item in headers]]
    for row in rows:
        data.append([paragraph(item, styles["tablecell"]) for item in row])
    return Table(
        data,
        colWidths=widths,
        repeatRows=1,
        style=TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f8f9")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        ),
    )


def build_pdf():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        rightMargin=1.55 * cm,
        leftMargin=1.55 * cm,
        topMargin=1.45 * cm,
        bottomMargin=1.8 * cm,
        title="Healthcare CTI SOC Website Workflow Guide",
        author="Healthcare CTI SOC",
    )
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("Title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=28, leading=33, textColor=NAVY, spaceAfter=12),
        "subtitle": ParagraphStyle("Subtitle", parent=base["Normal"], fontName="Helvetica", fontSize=13, leading=18, textColor=MUTED, spaceAfter=18),
        "h1": ParagraphStyle("H1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=NAVY, spaceBefore=4, spaceAfter=7),
        "h2": ParagraphStyle("H2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=INK, spaceBefore=10, spaceAfter=6),
        "body": ParagraphStyle("Body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.6, leading=14, textColor=INK, spaceAfter=7),
        "note": ParagraphStyle("Note", parent=base["BodyText"], fontName="Helvetica", fontSize=9.2, leading=13, textColor=INK),
        "stepnum": ParagraphStyle("StepNumber", parent=base["BodyText"], alignment=TA_CENTER, fontName="Helvetica-Bold", fontSize=10, leading=14, textColor=NAVY),
        "tablehead": ParagraphStyle("TableHead", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=colors.white),
        "tablecell": ParagraphStyle("TableCell", parent=base["BodyText"], fontName="Helvetica", fontSize=8.4, leading=11.5, textColor=INK),
    }
    story = []

    story.extend(
        [
            Spacer(1, 3.0 * cm),
            Paragraph("HEALTHCARE CTI SOC", styles["title"]),
            Paragraph("Detailed website workflow guide", styles["title"]),
            Paragraph(
                "How the dashboard turns static hospital cybersecurity data into simulated alerts enriched with current threat intelligence.",
                styles["subtitle"],
            ),
            Table(
                [[paragraph("<b>Purpose</b><br/>Explain every website action and what the system does behind the screen.", styles["note"]), paragraph("<b>Data model</b><br/>Static hospital and synthetic data; live intelligence from OSV, NVD, OTX, and VirusTotal.", styles["note"]) ]],
                colWidths=[8.0 * cm, 8.0 * cm],
                style=TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), MINT),
                        ("BOX", (0, 0), (-1, -1), 0.5, TEAL),
                        ("INNERGRID", (0, 0), (-1, -1), 0.35, TEAL),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 12),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                        ("TOPPADDING", (0, 0), (-1, -1), 12),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ]
                ),
            ),
            Spacer(1, 1.0 * cm),
            paragraph("Important: this is a security training and research system. The hospital events are static simulation data, not real hospital activity. The live provider responses can be current, but an automated score still requires analyst review before any operational decision.", styles["body"]),
            PageBreak(),
        ]
    )

    story.extend(section("1. What happens when you open the website", "The website is a local dashboard. It connects to the local CTI API through its own development proxy, so the browser does not need to call a separate port directly.", styles))
    story.append(numbered_step("1", "Open the dashboard", "Open <b>http://127.0.0.1:5173/</b>. The dashboard page is served by Vite. Requests that start with <b>/api</b> and <b>/ws</b> are proxied to the CTI API on port 8000.", styles))
    story.append(numbered_step("2", "Enter the administrator email and password", "The login form checks the entered email and password against the local development configuration. It does not send the password to OTX, VirusTotal, NVD, or OSV.", styles))
    story.append(numbered_step("3", "Request a one-time code", "When the credentials are correct, the API creates a short-lived OTP. In this development installation, the OTP may be configured locally for demonstration. In a real deployment, this step must use an approved identity provider or MFA service.", styles))
    story.append(numbered_step("4", "Verify the OTP", "The website sends the one-time code to the local API. On success, the dashboard stores only a local browser-session flag so the interface can open. The user is then taken to the threat operations dashboard.", styles))
    story.append(Spacer(1, 8))
    story.append(paragraph("If the login page ever says <b>Failed to fetch</b>, it means the browser could not reach the local API. The correct local setup is dashboard port 5173, API port 8000, and no stale VITE_API_URL or VITE_WS_URL override pointing to another port.", styles["note"]))

    story.append(PageBreak())
    story.extend(section("2. How the static hospital stream is used", "The website does not collect live hospital traffic. Instead, it replays records from approved static datasets and treats each as a simulated security event.", styles))
    story.append(data_table(
        ["Dataset", "Website use", "Privacy handling"],
        [
            ["WUSTL-EHMS-2020", "Provides labeled IoMT and healthcare-style network-flow telemetry. It supplies normal and attack-category event samples for the stream and ML model.", "Only network-flow values are used for cyber scoring."],
            ["Synthea FHIR R4 sample", "Provides a separate tokenized synthetic patient-context index for project context.", "Names, addresses, birth dates, and FHIR bundles are not sent to CTI providers."],
            ["Public IoC demonstration", "Provides harmless public indicators such as a public IP, domain, and the EICAR test-signature hash for live lookup demonstrations.", "Only public indicators are eligible for external enrichment."],
        ],
        [3.35 * cm, 7.25 * cm, 5.4 * cm], styles,
    ))
    story.append(Spacer(1, 12))
    story.append(numbered_step("5", "Receive a simulated event", "After dashboard login, the browser opens a WebSocket connection to <b>/ws/live-logs</b>. The API selects a static event from the configured categories and formats it as a live-looking dashboard record.", styles))
    story.append(numbered_step("6", "Read only cyber-security fields", "For each static record, the system considers only explicitly allow-listed fields: source IP, destination IP, domain, hostname, URL, file hash, MD5, SHA-1, SHA-256, and an explicit indicator list. It never parses clinical notes, patient context, or arbitrary metadata for IoCs.", styles))
    story.append(numbered_step("7", "Normalize and de-duplicate indicators", "Each candidate is normalized. For example, Example.COM. becomes example.com. Duplicate values from two fields are processed only once, while the original field name is retained as provenance for the audit record.", styles))

    story.append(PageBreak())
    story.extend(section("3. Privacy decision before any live lookup", "This is the key boundary between the static hospital data and the external internet.", styles))
    story.append(data_table(
        ["Indicator type", "What the system does", "External sharing"],
        [
            ["Private/local IPv4 or IPv6", "Records a local privacy verdict and keeps it in PostgreSQL for traceability.", "Never sent to OTX or VirusTotal."],
            ["Internal hostnames such as .local, .internal, or .lan", "Treats them as local assets rather than external IoCs.", "Never sent to external IoC services."],
            ["Public IP, public domain, URL, or file hash", "Normalizes the indicator and starts current IoC reputation lookups.", "May be sent to OTX and VirusTotal using the configured API keys."],
            ["Dependency/SBOM data", "Scans the project dependency inventory, lockfiles, source, or SBOM for known vulnerable packages.", "Checked against OSV; CVE details are enriched from NVD."],
        ],
        [3.3 * cm, 7.0 * cm, 5.7 * cm], styles,
    ))
    story.append(Spacer(1, 12))
    story.append(paragraph("The privacy decision is included in the event evidence. A private source IP is not treated as malicious merely because it is private; it is simply not eligible for external reputation lookup.", styles["body"]))
    story.append(Spacer(1, 5))
    story.append(Table([[paragraph("<b>Why this matters</b><br/>Hospital data may contain sensitive infrastructure details. The website separates local telemetry analysis from external reputation lookup so that only appropriate public IoCs cross the boundary.", styles["note"])]], colWidths=[16.0 * cm], style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff5de")), ("BOX", (0, 0), (-1, -1), 0.4, AMBER), ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)])))

    story.append(PageBreak())
    story.extend(section("4. The four live intelligence checks", "The static event remains static. What becomes live is the intelligence response returned at assessment time.", styles))
    story.append(data_table(
        ["Provider", "Input", "What the website obtains", "How it contributes"],
        [
            ["AlienVault OTX", "Public IP, domain, URL, or hash", "Pulse count, reputation, and validation information.", "Evidence that an indicator is linked to known campaigns or community-reported activity."],
            ["VirusTotal", "Public IP, domain, URL, or hash", "Multi-engine malicious, suspicious, harmless, and undetected counts plus reputation.", "Evidence of malware or reputation detections across scanning engines."],
            ["OSV / OSV-Scanner", "Project source, lockfile, SBOM, or dependency inventory", "Known vulnerable packages and aliases such as CVE IDs.", "Current software dependency exposure for the CTI application or supplied inventories."],
            ["NVD API 2.0", "CVE IDs discovered through OSV", "CVSS score, severity, CISA KEV status, due date, and required action when present.", "Prioritizes vulnerability exposure; it does not determine an IP reputation."],
        ],
        [2.55 * cm, 3.65 * cm, 5.0 * cm, 4.8 * cm], styles,
    ))
    story.append(Spacer(1, 12))
    story.append(numbered_step("8", "Use cache and request coalescing", "Before sending a duplicate live request, the service checks a TTL cache. If several dashboard clients request the same indicator at the same time, one live request is shared. This protects API quota and reduces repeated provider traffic.", styles))
    story.append(numbered_step("9", "Record provider coverage", "Each result indicates which sources were configured, queried, available, and whether the lookup was complete. A provider outage is shown as unavailable evidence, not silently converted into a clean result.", styles))
    story.append(numbered_step("10", "Refresh vulnerability posture", "The API periodically runs OSV scanning and then requests NVD CVE details. The dashboard's <b>Refresh scan</b> button can trigger this process on demand.", styles))

    story.append(PageBreak())
    story.extend(section("5. ML scoring and final classification", "The system does not train the ML model on OTX, VirusTotal, NVD, or OSV answers. The ML model scores network behavior; live evidence is added separately during inference.", styles))
    story.append(data_table(
        ["Evidence layer", "Examples", "Effect on final score"],
        [
            ["Static telemetry ML", "Ports, bytes, flow duration, packets, load, loss, and rate.", "Produces the base behavior probability. Patient and biometric data are excluded."],
            ["Live IoC evidence", "OTX pulses; VirusTotal malicious or suspicious engine counts.", "Raises confidence when a public indicator is currently associated with malicious activity."],
            ["Vulnerability posture", "OSV findings, NVD CVSS, and CISA known-exploited CVEs.", "Adds exposure context weighted by the affected asset's criticality."],
        ],
        [3.0 * cm, 6.5 * cm, 6.5 * cm], styles,
    ))
    story.append(Spacer(1, 12))
    story.append(paragraph("The final risk uses a bounded noisy-OR-style fusion so it cannot exceed 100%. The result contains: base ML probability, external-intelligence contribution, vulnerability-posture contribution, asset criticality, risk level, and readable reasons.", styles["body"]))
    story.append(data_table(
        ["Final classification", "When it is typically used"],
        [
            ["Active Attack", "A malicious domain, URL, or file hash is confirmed, or multiple providers confirm malicious evidence."],
            ["Malicious IP", "A public IP has live malicious reputation evidence."],
            ["Security Vulnerability", "A known CVE affects a software, firmware, service, SBOM, or dependency inventory item."],
            ["Unauthorized Access", "Behavioral risk is high even without a confirmed external IoC match."],
            ["Needs Review", "There is enough risk to preserve and review the event, but evidence is not sufficient for a stronger classification."],
        ],
        [4.2 * cm, 11.8 * cm], styles,
    ))

    story.append(PageBreak())
    story.extend(section("6. What you see and can do on the dashboard", "The dashboard presents the same evidence that is stored on the server. It is not a separate detection engine.", styles))
    story.append(numbered_step("11", "Watch the connection status", "The top status pill describes the WebSocket connection. <b>Live</b> means the browser is receiving simulated event records from the API. <b>Offline</b> means the browser is reconnecting or the local API is unavailable.", styles))
    story.append(numbered_step("12", "Read the metrics and categories", "Threat Events, Safe Traffic, Live Categories, and Observed Volume are calculated from the events currently saved in the browser window. The Public IoC demonstration category is for harmless live-lookup testing.", styles))
    story.append(numbered_step("13", "Review live intelligence and dependency posture", "The OSV, NVD, OTX, and VirusTotal cards show configuration and service status. The posture strip shows package count, findings, critical findings, known-exploited count, and maximum CVSS.", styles))
    story.append(numbered_step("14", "Review the persisted analyst queue", "This section reads final alerts from PostgreSQL. Each item shows the stored title, static event ID when available, final classification, score, severity, and current status. It is the server-side audit trail, not a browser-only warning.", styles))
    story.append(numbered_step("15", "Filter and export the event stream", "Use category, TLP, date, time, and search controls to narrow the visible event list. The export button downloads the currently filtered records as CSV from the browser's local dashboard history.", styles))
    story.append(numbered_step("16", "Preview or install a report", "For any visible event, Preview opens an incident-style report with the event fields and recommended actions. Install creates a PDF when the browser supports it; otherwise it downloads an HTML report fallback.", styles))

    story.append(PageBreak())
    story.extend(section("7. Database audit trail and safe operation", "PostgreSQL retains the evidence needed to explain why an alert was produced.", styles))
    story.append(data_table(
        ["Stored record", "Purpose"],
        [
            ["hospital_events", "Original static telemetry event and local flow features."],
            ["indicators and event_indicators", "Normalized indicators, public/private flag, source field, and event linkage."],
            ["cti_lookup_results", "Timestamped OTX, VirusTotal, OSV, and NVD raw responses and verdicts."],
            ["model_predictions", "Latest ML/fusion probability, risk level, predicted class, and feature snapshot."],
            ["alerts, alert_evidence, and cti_matches", "Final classification plus the ML and CTI evidence that supported it."],
            ["vulnerabilities and asset_vulnerabilities", "OSV/NVD vulnerability posture linked to the relevant application asset or component."],
        ],
        [5.1 * cm, 10.9 * cm], styles,
    ))
    story.append(Spacer(1, 13))
    story.append(Paragraph("Recommended analyst workflow", styles["h2"]))
    story.append(paragraph("1. Confirm the dashboard shows Live. 2. Review the event's source and destination context. 3. Check whether the indicator was private (not shared) or public (live-enriched). 4. Inspect OTX and VirusTotal provider evidence. 5. Review OSV/NVD posture when the alert concerns a vulnerable device or application. 6. Validate the alert with local firewall, endpoint, device, and asset-inventory records before calling it a confirmed incident. 7. Update the alert in the operational process, preserving this system's evidence as supporting context.", styles["body"]))
    story.append(Table([[paragraph("<b>Production warning</b><br/>This implementation is suitable for a local demonstration and coursework environment. Before use with real hospital operations, add enterprise authentication, role-based authorization, secure secret storage, TLS, centralized logging, backup and retention rules, provider-rate governance, data-protection assessment, and clinical-security governance approval.", styles["note"])]], colWidths=[16.0 * cm], style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fdebed")), ("BOX", (0, 0), (-1, -1), 0.4, RED), ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)])))

    document.build(story, onFirstPage=header_footer, onLaterPages=header_footer)


if __name__ == "__main__":
    build_pdf()
    print(OUTPUT)
