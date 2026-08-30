# backend/pdf_generator.py
"""
NIRIKSHAK-AI :: RBI CSIR & CERT-In Compliance PDF Report Generator

Generates a pristine, regulation-grade 1–2 page PDF threat report using ReportLab.
Features:
  - Defensive string escaping for all user-sourced data (XML-safe)
  - Multi-column summary table with crisp padding & font hierarchy
  - Shaded callout box for GenAI forensic narrative
  - Clean page numbering & RBI CSIR branded header on every page
  - Safe wrapping for SHA-256 hashes, long package names, and deep URLs
"""

import io
import logging
import re
import textwrap
from datetime import datetime
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import KeepTogether

logger = logging.getLogger("nirikshak.pdf_generator")

# ─── Page Geometry ────────────────────────────────────────────────────────────
PAGE_W, PAGE_H = A4
MARGIN = 15 * mm
CONTENT_W = PAGE_W - 2 * MARGIN
HEADER_H = 48 * mm          # slightly tighter header
FOOTER_H = 11 * mm
USABLE_H = PAGE_H - HEADER_H - FOOTER_H - 10 * mm

# ─── Colour Palette ──────────────────────────────────────────────────────────
_hex = colors.HexColor
C_NAVY       = _hex("#0A192F")
C_SLATE      = _hex("#112240")
C_CYAN       = _hex("#64FFDA")
C_WHITE      = colors.white
C_OFF_WHITE  = _hex("#F8FAFC")
C_LIGHT_GRAY = _hex("#F1F5F9")
C_MED_GRAY   = _hex("#94A3B8")
C_DARK_GRAY  = _hex("#334155")
C_CALLOUT_BG = _hex("#EFF6FF")
C_CALLOUT_BD = _hex("#3B82F6")
C_GRID       = _hex("#CBD5E1")
C_PERM_BLUE  = _hex("#1E40AF")
C_WARN_BG    = _hex("#FFF7ED")
C_WARN_BD    = _hex("#F97316")

SEVERITY_COLORS = {
    "CRITICAL": _hex("#EF4444"),
    "HIGH":     _hex("#F97316"),
    "MEDIUM":   _hex("#EAB308"),
    "LOW":      _hex("#10B981"),
}


# ═══════════════════════════════════════════════════════════════════════════════
#  STRING ESCAPING
# ═══════════════════════════════════════════════════════════════════════════════

def _safe(value, max_len: int = 200, fallback: str = "N/A") -> str:
    """
    Convert *any* value to a ReportLab-safe XML string.

    1.  ``None`` / blank → *fallback*
    2.  Strip non-printable code-points (keep tab, CR, LF)
    3.  XML-escape  & < > " '  (prevents Paragraph parser crashes)
    4.  Truncate to *max_len* with ellipsis
    5.  Insert zero-width spaces inside long unbroken tokens (>40 chars)
        so that Paragraph can word-wrap them (SHA-256, deep URLs, etc.)
    """
    if value is None:
        return fallback
    text = str(value).strip()
    if not text:
        return fallback

    # Strip non-printable (keep \t \n \r and unicode ≥ \u00A0)
    text = re.sub(r"[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]", "", text)

    # XML entity escaping — order matters (& first)
    text = (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))

    # Truncate
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."

    # Insert soft-break hints (zero-width space U+200B) every 40 chars
    # inside any unbroken token, so ReportLab can wrap it.
    text = re.sub(
        r"(\S{40})",
        lambda m: m.group(1) + "\u200B",
        text,
    )
    return text


def _safe_hash(sha: str) -> str:
    """Format a SHA-256 hash into two wrapped lines for the summary table."""
    sha = _safe(sha, max_len=70)
    if len(sha) > 35:
        return sha[:32] + "<br/>" + sha[32:]
    return sha


# ═══════════════════════════════════════════════════════════════════════════════
#  PARAGRAPH STYLE FACTORY
# ═══════════════════════════════════════════════════════════════════════════════

def _styles() -> dict:
    """Return a dictionary of all ParagraphStyles used in the report."""
    S = {}

    # ── Titles ────────────────────────────────────────────────────────────
    S["title"] = ParagraphStyle(
        "title",
        fontName="Helvetica-Bold", fontSize=16, leading=20,
        textColor=C_WHITE, alignment=TA_CENTER, spaceAfter=3,
    )
    S["subtitle"] = ParagraphStyle(
        "subtitle",
        fontName="Helvetica", fontSize=8, leading=11,
        textColor=C_CYAN, alignment=TA_CENTER, spaceAfter=2,
    )

    # ── Section header ────────────────────────────────────────────────────
    S["section"] = ParagraphStyle(
        "section",
        fontName="Helvetica-Bold", fontSize=10.5, leading=14,
        textColor=C_NAVY, spaceBefore=12, spaceAfter=5,
    )

    # ── Body ──────────────────────────────────────────────────────────────
    S["body"] = ParagraphStyle(
        "body",
        fontName="Helvetica", fontSize=8.5, leading=12.5,
        textColor=C_DARK_GRAY, alignment=TA_JUSTIFY, spaceAfter=4,
    )
    S["body_b"] = ParagraphStyle(
        "body_b",
        fontName="Helvetica-Bold", fontSize=8.5, leading=12.5,
        textColor=C_DARK_GRAY, spaceAfter=4,
    )

    # ── Table cells ───────────────────────────────────────────────────────
    S["th"] = ParagraphStyle(
        "th",
        fontName="Helvetica-Bold", fontSize=7.5, leading=10,
        textColor=C_WHITE, alignment=TA_CENTER,
    )
    S["td"] = ParagraphStyle(
        "td",
        fontName="Helvetica", fontSize=7.5, leading=10.5,
        textColor=C_DARK_GRAY, alignment=TA_LEFT,
        wordWrap="LTR",
    )
    S["td_c"] = ParagraphStyle(
        "td_c",
        fontName="Helvetica", fontSize=7.5, leading=10.5,
        textColor=C_DARK_GRAY, alignment=TA_CENTER,
    )
    S["td_label"] = ParagraphStyle(
        "td_label",
        fontName="Helvetica-Bold", fontSize=7.5, leading=10.5,
        textColor=C_NAVY, alignment=TA_LEFT,
    )
    S["td_mono"] = ParagraphStyle(
        "td_mono",
        fontName="Courier", fontSize=6.5, leading=9,
        textColor=C_PERM_BLUE, alignment=TA_LEFT,
        wordWrap="LTR",
    )

    # ── Callout box ───────────────────────────────────────────────────────
    S["callout"] = ParagraphStyle(
        "callout",
        fontName="Helvetica", fontSize=8, leading=12,
        textColor=C_DARK_GRAY, alignment=TA_JUSTIFY, spaceAfter=2,
    )
    S["callout_b"] = ParagraphStyle(
        "callout_b",
        fontName="Helvetica-Bold", fontSize=8, leading=12,
        textColor=C_DARK_GRAY, spaceAfter=2,
    )

    # ── Footer ────────────────────────────────────────────────────────────
    S["footer"] = ParagraphStyle(
        "footer",
        fontName="Helvetica", fontSize=6.5, leading=9,
        textColor=C_MED_GRAY, alignment=TA_CENTER,
    )

    # ── Permission list ───────────────────────────────────────────────────
    S["perm"] = ParagraphStyle(
        "perm",
        fontName="Courier", fontSize=7, leading=9.5,
        textColor=C_PERM_BLUE, spaceAfter=1,
    )

    return S


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE HEADER / FOOTER CALLBACK
# ═══════════════════════════════════════════════════════════════════════════════

def _draw_header_footer(canvas, doc, data: dict):
    """Draws the branded header band and numbered footer on every page."""
    canvas.saveState()

    # ── Header banner ─────────────────────────────────────────────────────
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, PAGE_H - HEADER_H, PAGE_W, HEADER_H, fill=1, stroke=0)

    # Brand
    canvas.setFont("Helvetica-Bold", 15)
    canvas.setFillColor(C_WHITE)
    canvas.drawString(MARGIN, PAGE_H - 18 * mm, "NIRIKSHAK-AI")

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(C_CYAN)
    canvas.drawString(MARGIN, PAGE_H - 24 * mm, "Mobile Banking Malware Analysis Platform")

    # Compliance tags (right side)
    canvas.setFont("Helvetica-Bold", 6.5)
    canvas.setFillColor(C_CYAN)
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 15 * mm, "RBI CSIR COMPLIANT")
    canvas.setFillColor(C_MED_GRAY)
    canvas.setFont("Helvetica", 6.5)
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 21 * mm, "CERT-In GUIDELINES ALIGNED")

    # Severity pill
    severity = str(data.get("severity_tier", "UNKNOWN"))
    score = data.get("final_score", 0)
    pill_color = SEVERITY_COLORS.get(severity, colors.gray)

    pill_w, pill_h = 44 * mm, 8 * mm
    pill_x = PAGE_W - MARGIN - pill_w
    pill_y = PAGE_H - 36 * mm
    canvas.setFillColor(pill_color)
    canvas.roundRect(pill_x, pill_y, pill_w, pill_h, 2 * mm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_WHITE)
    canvas.drawCentredString(
        pill_x + pill_w / 2,
        pill_y + 2.2 * mm,
        f"THREAT: {severity}  ({score:.1f}/100)",
    )

    # Accent line
    canvas.setStrokeColor(C_CYAN)
    canvas.setLineWidth(1.5)
    accent_y = PAGE_H - HEADER_H - 1
    canvas.line(0, accent_y, PAGE_W, accent_y)

    # ── Footer ────────────────────────────────────────────────────────────
    canvas.setFillColor(C_LIGHT_GRAY)
    canvas.rect(0, 0, PAGE_W, FOOTER_H, fill=1, stroke=0)

    canvas.setFont("Helvetica", 6)
    canvas.setFillColor(C_MED_GRAY)
    canvas.drawString(
        MARGIN, 4 * mm,
        "CONFIDENTIAL \u2014 For Authorised Security Personnel Only  |  "
        "Generated by NIRIKSHAK-AI v1.0",
    )
    canvas.drawRightString(
        PAGE_W - MARGIN, 4 * mm,
        f"Page {doc.page}  |  {_safe(data.get('timestamp'), max_len=30)}",
    )

    canvas.restoreState()


# ═══════════════════════════════════════════════════════════════════════════════
#  TABLE PADDING HELPER — DRY base style
# ═══════════════════════════════════════════════════════════════════════════════

_BASE_CELL = [
    ("TOPPADDING",    (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
]


def _zebra(rows_count: int, even=C_WHITE, odd=C_LIGHT_GRAY) -> list:
    """Return alternating-row background commands for a TableStyle."""
    cmds = []
    for i in range(1, rows_count):
        bg = even if i % 2 != 0 else odd
        cmds.append(("BACKGROUND", (0, i), (-1, i), bg))
    return cmds


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION BUILDERS
# ═══════════════════════════════════════════════════════════════════════════════

def _section_rule(title: str, S: dict) -> list:
    """Return [Paragraph, HRFlowable] for a numbered section heading."""
    return [
        Paragraph(title, S["section"]),
        HRFlowable(width="100%", thickness=0.5, color=C_CYAN, spaceAfter=5),
    ]


# ── 1. Case Summary Table ────────────────────────────────────────────────────

def _summary_table(data: dict, S: dict) -> Table:
    """4-column key-value summary: Package, SHA-256, Timestamp, Score, Components, etc."""

    sha_raw = data.get("sha256", "N/A")
    sha_display = _safe_hash(sha_raw)

    sha1_raw = data.get("sha1", "N/A")
    sha1_display = _safe_hash(sha1_raw)

    file_bytes = data.get("file_size_bytes", 0)
    if file_bytes > 1024 * 1024:
        size_display = f"{file_bytes / (1024 * 1024):.2f} MB ({file_bytes:,} bytes)"
    elif file_bytes > 0:
        size_display = f"{file_bytes / 1024:.1f} KB ({file_bytes:,} bytes)"
    else:
        size_display = "N/A"

    act_cnt = data.get("activities_count", 0)
    srv_cnt = data.get("services_count", 0)
    rcv_cnt = data.get("receivers_count", 0)
    prv_cnt = data.get("providers_count", 0)
    comp_display = f"{act_cnt} Act / {srv_cnt} Srv / {rcv_cnt} Rcv / {prv_cnt} Prv"

    target_sdk = data.get("target_sdk")
    min_sdk = data.get("min_sdk")

    rows = [
        # Header row
        [Paragraph("FIELD", S["th"]),
         Paragraph("VALUE", S["th"]),
         Paragraph("FIELD", S["th"]),
         Paragraph("VALUE", S["th"])],
        # Row 1
        [Paragraph("Package Name", S["td_label"]),
         Paragraph(_safe(data.get("package_name"), max_len=48), S["td"]),
         Paragraph("App Name", S["td_label"]),
         Paragraph(_safe(data.get("app_name"), max_len=36), S["td"])],
        # Row 2
        [Paragraph("SHA-256 Hash", S["td_label"]),
         Paragraph(sha_display, S["td_mono"]),
         Paragraph("Timestamp", S["td_label"]),
         Paragraph(_safe(data.get("timestamp"), max_len=30), S["td"])],
        # Row 3
        [Paragraph("SHA-1 Hash", S["td_label"]),
         Paragraph(sha1_display, S["td_mono"]),
         Paragraph("File Size", S["td_label"]),
         Paragraph(_safe(size_display), S["td"])],
        # Row 4
        [Paragraph("Target SDK", S["td_label"]),
         Paragraph(f"Android API {_safe(target_sdk)}" if target_sdk is not None else "Unknown", S["td_c"]),
         Paragraph("Min SDK", S["td_label"]),
         Paragraph(f"Android API {_safe(min_sdk)}" if min_sdk is not None else "Unknown", S["td_c"])],
        # Row 5
        [Paragraph("Manifest Components", S["td_label"]),
         Paragraph(_safe(comp_display), S["td"]),
         Paragraph("Indian Target", S["td_label"]),
         Paragraph(
             "<font color='#EF4444'><b>\u26A0 DETECTED</b></font>"
             if data.get("target_detected") or data.get("is_indian_vector")
             else "<font color='#10B981'><b>\u2714 Not Detected</b></font>", S["td"])],
        # Row 6
        [Paragraph("Threat Score", S["td_label"]),
         Paragraph(f"<b>{data.get('final_score', 0):.1f}</b> / 100 ({_safe(data.get('severity_tier', 'LOW'))})", S["td"]),
         Paragraph("Primary Exploit", S["td_label"]),
         Paragraph(_safe(str(data.get("primary_exploit", "UNKNOWN")).replace("_", " "), max_len=36), S["td"])],
    ]

    widths = [3.2 * cm, 5.8 * cm, 3.2 * cm, 5.8 * cm]
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        # Header
        ("BACKGROUND",  (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
        # Grid
        ("GRID",        (0, 0), (-1, -1), 0.4, C_GRID),
        ("BOX",         (0, 0), (-1, -1), 1,   C_NAVY),
        *_BASE_CELL,
        *_zebra(len(rows)),
    ]))
    return t


# ── 2. Score Breakdown Table ──────────────────────────────────────────────────

def _score_table(data: dict, S: dict) -> Table:
    """5-Factor risk fusion contribution table with points and weights."""
    p_ml_pts = data.get("p_ml_contribution", 0.0)
    sem_pts = data.get("semantic_contribution", 0.0)
    dyn_pts = data.get("dynamic_contribution", 0.0)
    bonus_pts = data.get("target_bonus_applied", 0.0)

    rows = [[
        Paragraph("ANALYSIS FACTOR", S["th"]),
        Paragraph("POINTS EARNED", S["th"]),
        Paragraph("MAX WEIGHT", S["th"]),
    ]]

    rows.append([
        Paragraph("ML Static / Permission Analysis (XGBoost)", S["td"]),
        Paragraph(f"<b>{p_ml_pts:.1f}</b> pts", S["td_c"]),
        Paragraph("35 pts (35%)", S["td_c"]),
    ])
    rows.append([
        Paragraph("GenAI Semantic Code Analysis (Groq AI)", S["td"]),
        Paragraph(f"<b>{sem_pts:.1f}</b> pts", S["td_c"]),
        Paragraph("40 pts (40%)", S["td_c"]),
    ])
    rows.append([
        Paragraph("Dynamic Cloud Sandbox (VirusTotal)", S["td"]),
        Paragraph(f"<b>{dyn_pts:.1f}</b> pts", S["td_c"]),
        Paragraph("25 pts (25%)", S["td_c"]),
    ])
    if bonus_pts > 0 or data.get("target_detected") or data.get("is_indian_vector"):
        rows.append([
            Paragraph("<font color='#EF4444'><b>Indian Target Vector Bonus</b></font>", S["td"]),
            Paragraph(f"<font color='#EF4444'><b>+{bonus_pts:.1f}</b> pts</font>", S["td_c"]),
            Paragraph("+5 pts (+5%)", S["td_c"]),
        ])

    widths = [9.0 * cm, 4.5 * cm, 4.5 * cm]
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), C_SLATE),
        ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
        ("GRID",        (0, 0), (-1, -1), 0.4, C_GRID),
        ("BOX",         (0, 0), (-1, -1), 1,   C_SLATE),
        ("ALIGN",       (1, 1), (2, -1), "CENTER"),
        *_BASE_CELL,
        *_zebra(len(rows)),
    ]))
    return t


# ── 3. Forensic Narrative Callout ─────────────────────────────────────────────

def _narrative_callout(data: dict, S: dict) -> KeepTogether:
    """Shaded box with a thick left/top accent for the AI narrative."""
    narrative = _safe(data.get("forensic_narrative",
                               "No narrative available from the AI engine."), max_len=900)
    exploit   = _safe(data.get("primary_exploit", "UNKNOWN"), max_len=40)
    indian    = "YES \u26A0" if data.get("is_indian_vector") else "No"
    conf      = _safe(data.get("confidence", "LOW"), max_len=10)

    meta_para = Paragraph(
        f"<b>Exploit:</b> {exploit} &nbsp;&nbsp; "
        f"<b>Indian Vector:</b> {indian} &nbsp;&nbsp; "
        f"<b>AI Confidence:</b> {conf}",
        S["callout_b"],
    )
    body_para = Paragraph(
        f"<b>Forensic Analysis:</b><br/>{narrative}",
        S["callout"],
    )

    rows = [[meta_para], [body_para]]
    t = Table(rows, colWidths=[CONTENT_W - 4 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_CALLOUT_BG),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("BOX",           (0, 0), (-1, -1), 1.5, C_CALLOUT_BD),
        ("LINEABOVE",     (0, 0), (-1, 0),  3.5, C_CALLOUT_BD),  # thick top accent
        ("LINEBEFORE",    (0, 0), (0, -1),  3.5, C_CALLOUT_BD),  # thick left accent
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return KeepTogether(t)


# ── 3.5. Attack Chain Flow ─────────────────────────────────────────────────────

def _attack_chain_table(data: dict, S: dict) -> Table:
    """Digital Twin / Attack Chain sequence."""
    exploit = str(data.get("primary_exploit", "TROJAN_OVERLAY")).replace("_", " ")
    runtime = data.get("runtime_events", [])
    network = data.get("network_iocs", [])
    perms = data.get("dangerous_permissions", [])

    pkg = data.get("package_name", "com.malware.app")
    
    perm_detail = "Requested SMS & Accessibility privileges"
    if perms:
        perm_detail = ", ".join(str(p).replace("android.permission.", "") for p in perms[:2])
        if len(perms) > 2:
            perm_detail += f" and {len(perms)-2} others"
            
    intercept_detail = runtime[0] if runtime else "Real-time SMS broadcast & UI window scraping"
    c2_detail = network[0] if network else "Credentials & 2FA tokens transmitted over encrypted channel"

    rows = [
        [Paragraph("PHASE", S["th"]), Paragraph("STEP", S["th"]), Paragraph("ACTIVITY DETAILS", S["th"])]
    ]
    
    steps = [
        ("01", "Sideload / Install", f"Sideloaded APK ({pkg})"),
        ("02", "Permission Grant", perm_detail),
        ("03", "OTP / Window Intercept", intercept_detail),
        ("04", "C2 Exfiltration", c2_detail)
    ]
    
    for idx, name, desc in steps:
        rows.append([
            Paragraph(f"<b>STEP {idx}</b>", S["td_c"]),
            Paragraph(f"<b>{name}</b>", S["td"]),
            Paragraph(_safe(desc, max_len=150), S["td"])
        ])

    widths = [2 * cm, 4.5 * cm, 10.5 * cm]
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), C_SLATE),
        ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
        ("GRID",        (0, 0), (-1, -1), 0.4, C_GRID),
        ("BOX",         (0, 0), (-1, -1), 1,   C_SLATE),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        *_BASE_CELL,
        *_zebra(len(rows)),
    ]))
    return t


# ── 4. Dangerous Permissions Table ────────────────────────────────────────────

_PERM_RISK = {
    "android.permission.READ_SMS":                   "OTP / banking transaction interception",
    "android.permission.SEND_SMS":                   "Unauthorised SMS-based banking commands",
    "android.permission.RECEIVE_SMS":                "Real-time OTP harvesting",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "UI overlay &amp; keylogging (ATS attacks)",
    "android.permission.BIND_DEVICE_ADMIN":          "Device lockout / ransomware capability",
    "android.permission.INSTALL_PACKAGES":           "Dropper / secondary payload installation",
    "android.permission.READ_CONTACTS":              "Contact exfiltration for smishing campaigns",
    "android.permission.PROCESS_OUTGOING_CALLS":     "USSD banking call interception",
    "android.permission.RECORD_AUDIO":               "Voice / TOTP audio interception",
    "android.permission.ACCESS_FINE_LOCATION":       "User geolocation tracking",
    "android.permission.CAMERA":                     "Screen / document capture",
    "android.permission.SYSTEM_ALERT_WINDOW":        "Overlay phishing UI injection",
    "android.permission.READ_PHONE_STATE":           "IMEI harvesting for device binding",
    "android.permission.CALL_PHONE":                 "Silent USSD dialling / call forwarding",
    "android.permission.READ_CALL_LOG":              "Banking helpline call-log analysis",
    "android.permission.WRITE_EXTERNAL_STORAGE":     "File-system payload staging",
}


def _permissions_table(data: dict, S: dict) -> Optional[Table]:
    """Dangerous permissions with risk implications. Returns None if empty."""
    perms = data.get("dangerous_permissions", [])
    if not perms:
        return None

    rows = [[
        Paragraph("DANGEROUS PERMISSION", S["th"]),
        Paragraph("RISK IMPLICATION", S["th"]),
    ]]
    for perm in perms[:14]:  # cap at 14 for page space
        short = _safe(str(perm).replace("android.permission.", ""), max_len=45)
        risk  = _PERM_RISK.get(perm, "Elevated privilege \u2014 review required")
        rows.append([
            Paragraph(f"\u2022 {short}", S["perm"]),
            Paragraph(_safe(risk, max_len=80), S["td"]),
        ])

    widths = [8 * cm, 10 * cm]
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), C_PERM_BLUE),
        ("TEXTCOLOR",   (0, 0), (-1, 0), C_WHITE),
        ("GRID",        (0, 0), (-1, -1), 0.4, C_GRID),
        ("BOX",         (0, 0), (-1, -1), 1,   C_PERM_BLUE),
        *_BASE_CELL,
        *_zebra(len(rows)),
    ]))
    return t


# ── 5. Indian Banking Target Indicators ───────────────────────────────────────

def _targets_callout(data: dict, S: dict) -> Optional[KeepTogether]:
    """Orange warning callout listing matched Indian banking identifiers."""
    targets = data.get("matched_targets", [])
    if not targets:
        return None

    lines = "<br/>".join(f"\u2022 {_safe(t, max_len=75)}" for t in targets[:12])
    para = Paragraph(
        f"<b>\u26A0 WARNING:</b> The following Indian banking / UPI identifiers "
        f"were detected in the APK:<br/><br/>{lines}",
        S["callout"],
    )
    t = Table([[para]], colWidths=[CONTENT_W - 4 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_WARN_BG),
        ("BOX",           (0, 0), (-1, -1), 1.5, C_WARN_BD),
        ("LINEABOVE",     (0, 0), (-1, 0),  3.5, C_WARN_BD),
        ("LINEBEFORE",    (0, 0), (0, -1),  3.5, C_WARN_BD),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    return KeepTogether(t)


# ── 6. Recommended Action ────────────────────────────────────────────────────

def _action_callout(data: dict, S: dict) -> KeepTogether:
    """Severity-coloured callout with recommended response actions."""
    severity = str(data.get("severity_tier", "LOW"))
    accent   = SEVERITY_COLORS.get(severity, colors.green)
    risk     = _safe(data.get("risk_summary", ""), max_len=400)
    action   = _safe(data.get("recommended_action", "Manual review required."), max_len=600)

    rows = []
    if risk:
        rows.append([Paragraph(f"<b>Risk Assessment:</b><br/>{risk}", S["callout"])])
    rows.append([Paragraph(f"<b>Action Required:</b><br/>{action}", S["callout"])])

    t = Table(rows, colWidths=[CONTENT_W - 4 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_LIGHT_GRAY),
        ("BOX",           (0, 0), (-1, -1), 1.5, accent),
        ("LINEABOVE",     (0, 0), (-1, 0),  3.5, accent),
        ("LINEBEFORE",    (0, 0), (0, -1),  3.5, accent),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return KeepTogether(t)


# ═══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API — generate_pdf_report()
# ═══════════════════════════════════════════════════════════════════════════════

def generate_pdf_report(analysis_data: dict, output_path: Optional[str] = None) -> bytes:
    """
    Generate a full RBI CSIR & CERT-In compliance PDF threat report.

    Args:
        analysis_data: Merged dict from static + semantic + scoring outputs.
        output_path:   If set, also write the PDF to this file path.

    Returns:
        Raw PDF bytes.
    """
    logger.info("Generating PDF report for: %s",
                analysis_data.get("package_name", "unknown"))

    # Ensure timestamp is always present
    if not analysis_data.get("timestamp"):
        analysis_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S IST")

    # Defensive: coerce score to float
    try:
        analysis_data["final_score"] = float(analysis_data.get("final_score", 0))
    except (TypeError, ValueError):
        analysis_data["final_score"] = 0.0

    buf = io.BytesIO()
    S = _styles()

    # ── Page template ─────────────────────────────────────────────────────
    def _on_page(canvas, doc):
        _draw_header_footer(canvas, doc, analysis_data)

    frame = Frame(
        MARGIN,                              # x
        FOOTER_H + 4 * mm,                   # y
        CONTENT_W,                           # width
        USABLE_H,                            # height
        leftPadding=0, rightPadding=0,
        topPadding=3 * mm, bottomPadding=0,
    )

    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        pageTemplates=[PageTemplate(id="main", frames=[frame], onPage=_on_page)],
        rightMargin=MARGIN, leftMargin=MARGIN,
        topMargin=HEADER_H + 3 * mm,
        bottomMargin=FOOTER_H + 4 * mm,
        title="NIRIKSHAK-AI Threat Analysis Report",
        author="NIRIKSHAK-AI Security Platform",
        subject=f"APK Threat Report: {analysis_data.get('package_name', 'Unknown')}",
    )

    story: list = []

    # ─── § 1  CASE SUMMARY ────────────────────────────────────────────────
    story.extend(_section_rule("1. CASE SUMMARY", S))
    story.append(_summary_table(analysis_data, S))
    story.append(Spacer(1, 8))

    # ─── § 2  RISK SCORE ─────────────────────────────────────────────────
    story.extend(_section_rule("2. 5-FACTOR RISK FUSION SCORE", S))

    score_val = analysis_data.get("final_score", 0)
    severity  = str(analysis_data.get("severity_tier", "LOW"))
    bars      = int(score_val / 5)
    bar_str   = "\u2588" * bars + "\u2591" * (20 - bars)
    story.append(Paragraph(
        f"<font face='Courier' size='8'>{bar_str}</font>  "
        f"<b>{score_val:.1f}/100</b> \u2014 <b>{severity}</b>",
        S["body"],
    ))
    story.append(Spacer(1, 4))
    story.append(_score_table(analysis_data, S))
    story.append(Spacer(1, 8))

    story.extend(_section_rule(
        "3. AI FORENSIC NARRATIVE (Groq AI · llama-3.3-70b-versatile)", S))
    story.append(_narrative_callout(analysis_data, S))
    story.append(Spacer(1, 8))

    # ─── § 4 DIGITAL TWIN / ATTACK CHAIN ──────────────────────────────────────────
    story.extend(_section_rule("4. DIGITAL TWIN / ATTACK CHAIN FLOW", S))
    story.append(_attack_chain_table(analysis_data, S))
    story.append(Spacer(1, 8))

    # ─── § 5  APK SIGNING CERTIFICATE ───────────────────────────────────────
    story.extend(_section_rule("5. APK SIGNING CERTIFICATE", S))
    cert_data = analysis_data.get("cert_analysis", {})
    if cert_data:
        risk_flags = cert_data.get("risk_flags", [])
        risk_flags_str = ", ".join(risk_flags) if risk_flags else "None (Clean)"
        boost = cert_data.get("cert_risk_boost", 0.0)

        c_rows = [
            [Paragraph("Cert Status", S["td_label"]),
             Paragraph(
                 f"<font color='#EF4444'><b>\u26A0 Flagged ({risk_flags_str})</b></font> (+{int(boost*100)}% risk)"
                 if risk_flags else "<font color='#10B981'><b>\u2714 Valid &amp; Properly Signed</b></font>",
                 S["td"]
             )],
            [Paragraph("Self-Signed", S["td_label"]), Paragraph("YES" if cert_data.get("is_self_signed") else ("NO" if cert_data.get("cert_found") else "N/A"), S["td"])],
            [Paragraph("Subject", S["td_label"]), Paragraph(_safe(cert_data.get("subject", "Unknown"), max_len=120), S["td_mono"])],
            [Paragraph("Issuer", S["td_label"]), Paragraph(_safe(cert_data.get("issuer", "Unknown"), max_len=120), S["td_mono"])],
            [Paragraph("Valid From", S["td_label"]), Paragraph(_safe(cert_data.get("valid_from", "N/A")), S["td"])],
            [Paragraph("Valid To", S["td_label"]), Paragraph(_safe(cert_data.get("valid_to", "N/A")), S["td"])],
            [Paragraph("Validity Period", S["td_label"]), Paragraph(f"{cert_data.get('days_valid', 0)} days" if cert_data.get('days_valid') is not None else "N/A", S["td"])],
        ]
        from reportlab.platypus import Table, TableStyle
        cert_t = Table(c_rows, colWidths=[3.5 * cm, 13.5 * cm])
        cert_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), C_NAVY),
            ("TEXTCOLOR", (0, 0), (0, -1), C_WHITE),
            ("ROWBACKGROUNDS", (1, 0), (1, -1), [C_WHITE, _hex("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.3, C_MED_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(cert_t)
    else:
        story.append(Paragraph("No signing certificate could be extracted from this APK.", S["body"]))
    story.append(Spacer(1, 8))

    # ─── § 6  DANGEROUS PERMISSIONS ───────────────────────────────────────
    story.extend(_section_rule("6. DANGEROUS PERMISSIONS ANALYSIS", S))
    perm_t = _permissions_table(analysis_data, S)
    if perm_t:
        story.append(perm_t)
    else:
        story.append(Paragraph(
            "No dangerous permissions detected in this APK.", S["body"]))
    story.append(Spacer(1, 8))

    # ─── § 7  INDIAN BANKING TARGETS ──────────────────────────────────────
    story.extend(_section_rule("7. INDIAN BANKING TARGET INDICATORS", S))
    tgt = _targets_callout(analysis_data, S)
    if tgt:
        story.append(tgt)
    else:
        story.append(Paragraph(
            "No Indian banking, UPI, or USSD forwarding identifiers were "
            "detected in this APK. Indian targeting cannot be confirmed "
            "from static analysis alone.", S["body"]))
    story.append(Spacer(1, 8))

    # ─── § 8  MITRE ATT&CK MOBILE TECHNIQUES ──────────────────────────────
    story.extend(_section_rule("8. MITRE ATT\u00e9CK\u00ae MOBILE FRAMEWORK MAPPING", S))
    mitre_techniques = analysis_data.get("mitre_techniques", [])
    if mitre_techniques:
        mitre_data = [["Technique ID", "Technique Name", "Tactic", "Severity"]]
        for t in mitre_techniques[:12]:
            mitre_data.append([
                _safe(t.get("technique_id", "")),
                _safe(t.get("technique_name", "")),
                _safe(t.get("tactic", "")),
                _safe(t.get("severity", "")),
            ])
        from reportlab.platypus import Table, TableStyle
        mitre_t = Table(mitre_data, colWidths=[2.8 * cm, 7.2 * cm, 4.5 * cm, 2.5 * cm])
        mitre_t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  _hex("#1e3a5f")),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  C_WHITE),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, _hex("#f8fafc")]),
            ("TEXTCOLOR",   (0, 1), (-1, -1), C_DARK_GRAY),
            ("GRID",        (0, 0), (-1, -1), 0.3, C_GRID),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(mitre_t)
    else:
        story.append(Paragraph("No MITRE ATT&CK Mobile techniques were mapped from this APK.", S["body"]))
    story.append(Spacer(1, 8))

    # ─── § 9  INDICATORS OF COMPROMISE ────────────────────────────────────
    story.extend(_section_rule("9. INDICATORS OF COMPROMISE (IOCs)", S))
    iocs = analysis_data.get("iocs", [])
    if iocs:
        ioc_data = [["Type", "Indicator", "Classification", "Risk"]]
        for ioc in iocs[:15]:
            ioc_data.append([
                _safe(ioc.get("type", "").replace("_", " ")),
                _safe(ioc.get("value", ""), max_len=60),
                _safe(ioc.get("classification", "")),
                _safe(ioc.get("risk_level", "")),
            ])
        from reportlab.platypus import Table, TableStyle
        ioc_t = Table(ioc_data, colWidths=[3.2 * cm, 7.8 * cm, 3.8 * cm, 2.2 * cm])
        ioc_t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  _hex("#7f1d1d")),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  C_WHITE),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, _hex("#f8fafc")]),
            ("TEXTCOLOR",   (0, 1), (0, -1),  _hex("#b91c1c")),
            ("TEXTCOLOR",   (1, 1), (-1, -1), C_DARK_GRAY),
            ("GRID",        (0, 0), (-1, -1), 0.3, C_GRID),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(ioc_t)
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "\u26a0\ufe0f Share these IOCs with CERT-In and your SOC team for immediate blocking.",
            S["body"]))
    else:
        story.append(Paragraph("No hardcoded IOCs were extracted from this APK.", S["body"]))
    story.append(Spacer(1, 8))

    # ─── § 10  INCIDENT RESPONSE CHECKLIST ──────────────────────────────────
    story.extend(_section_rule("10. IMMEDIATE INCIDENT RESPONSE CHECKLIST", S))
    
    checklist_data = [
        ["Phase", "Action Required", "Status"],
        ["CONTAINMENT", "Isolate device from corporate and home networks (Airplane mode).", "[  ]"],
        ["CONTAINMENT", "Revoke any compromised SSO/Identity tokens associated with device.", "[  ]"],
        ["ERADICATION", "Do NOT connect device to PC via USB without write-blocking.", "[  ]"],
        ["ERADICATION", "Factory reset device (do NOT restore from recent cloud backup).", "[  ]"],
        ["RECOVERY", "Reset passwords for banking, UPI, and email accounts.", "[  ]"],
        ["RECOVERY", "Monitor network logs for IOCs listed in Section 9.", "[  ]"],
        ["REPORTING", "File FIR and report to CERT-In / Cyber Cell India.", "[  ]"],
    ]
    from reportlab.platypus import Table, TableStyle
    chk_t = Table(checklist_data, colWidths=[3.5 * cm, 11.5 * cm, 2.0 * cm])
    chk_t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  C_NAVY),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  C_CYAN),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, _hex("#f8fafc")]),
        ("TEXTCOLOR",   (0, 1), (-1, -1), C_DARK_GRAY),
        ("FONTNAME",    (0, 1), (0, -1),  "Helvetica-Bold"),
        ("ALIGN",       (2, 0), (2, -1),  "CENTER"),
        ("GRID",        (0, 0), (-1, -1), 0.3, C_GRID),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(chk_t)
    story.append(Spacer(1, 8))

    # ─── § 11 RECOMMENDED ACTION ──────────────────────────────────────────
    story.extend(_section_rule("11. REGULATORY RECOMMENDATION", S))
    story.append(_action_callout(analysis_data, S))
    story.append(Spacer(1, 8))

    # ─── § 12 CYBER CELL REPORTING INSTRUCTIONS ───────────────────────────
    story.extend(_section_rule("12. HOW TO REPORT TO CYBER CELL INDIA", S))

    story.append(Paragraph(
        "If this APK was received via WhatsApp, SMS, email, or phishing link, "
        "report it immediately to the National Cyber Crime Reporting Portal.",
        S["body"]))
    story.append(Spacer(1, 4))
    for step in [
        "1. Visit: https://cybercrime.gov.in",
        "2. Call National Cyber Crime Helpline: 1930 (24x7)",
        f"3. Reference SHA-256: {_safe(analysis_data.get('sha256', 'N/A'), max_len=70)}",
        "4. Attach this PDF report as evidence",
        "5. Contact your bank's fraud helpline to freeze accounts if credentials were exposed",
    ]:
        story.append(Paragraph(step, S["body"]))
        story.append(Spacer(1, 2))
    story.append(Spacer(1, 8))

    # ─── § 7  COMPLIANCE DISCLAIMER ───────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.4, color=C_MED_GRAY,
                            spaceAfter=5))
    story.append(Paragraph(
        "<b>Regulatory Disclaimer:</b> This report has been generated in "
        "alignment with RBI Cyber Security Framework (CSIR) guidelines, "
        "CERT-In Incident Response Standards (IT Act 2000, Section 8.B), "
        "and NPCI security audit requirements. This report is classified "
        "<b>CONFIDENTIAL</b> and intended solely for authorised security "
        "personnel and incident response teams. Unauthorised disclosure "
        "is prohibited.",
        S["body"],
    ))
    story.append(Spacer(1, 3))
    story.append(Paragraph(
        "NIRIKSHAK-AI is an automated analysis tool. All findings must be "
        "reviewed and validated by a qualified security analyst before "
        "initiating enforcement or legal actions.",
        S["body"],
    ))

    # ── Build PDF ─────────────────────────────────────────────────────────
    try:
        doc.build(story)
    except Exception as exc:
        logger.error("PDF build failed: %s", exc, exc_info=True)
        raise

    pdf_bytes = buf.getvalue()
    buf.close()

    if output_path:
        try:
            with open(output_path, "wb") as f:
                f.write(pdf_bytes)
            logger.info("PDF saved to: %s (%d bytes)", output_path, len(pdf_bytes))
        except OSError as exc:
            logger.error("Failed to save PDF to %s: %s", output_path, exc)

    logger.info("PDF report generated: %d bytes", len(pdf_bytes))
    return pdf_bytes
