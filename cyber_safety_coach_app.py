import base64
import json
import os
import re
from typing import Any

import streamlit as st
from openai import OpenAI


st.set_page_config(
    page_title="Scam Shield",
    page_icon="shield",
    layout="wide",
)


RISK_STYLES = {
    "Safe": {"bg": "#E8F5E9", "fg": "#1B5E20", "border": "#66BB6A"},
    "Suspicious": {"bg": "#FFF8E1", "fg": "#8D6E00", "border": "#FBC02D"},
    "High Risk": {"bg": "#FDECEC", "fg": "#B71C1C", "border": "#EF5350"},
}

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_label": {
            "type": "string",
            "enum": ["Safe", "Suspicious", "High Risk"],
        },
        "top_3_reasons": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 3,
            "maxItems": 3,
        },
        "action_checklist": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 3,
        },
    },
    "required": ["risk_label", "top_3_reasons", "action_checklist"],
    "additionalProperties": False,
}

DEMO_SIGNALS = [
    (
        "asks_for_credentials",
        3,
        [
            "password",
            "passcode",
            "login",
            "verify your account",
            "confirm your account",
            "sign in",
            "one-time code",
        ],
        "It asks for login or account details, which is a common phishing tactic.",
    ),
    (
        "asks_for_payment",
        3,
        [
            "credit card",
            "card details",
            "bank account",
            "payment details",
            "gift card",
            "wire transfer",
            "invoice",
            "pay now",
        ],
        "It asks for money or payment information in a risky way.",
    ),
    (
        "creates_urgency",
        2,
        [
            "urgent",
            "immediately",
            "within 24 hours",
            "act now",
            "suspended",
            "locked",
            "final notice",
            "today",
        ],
        "It creates pressure to act fast before you can slow down and verify it.",
    ),
    (
        "suspicious_link",
        2,
        [
            "http://",
            "bit.ly",
            "tinyurl",
            "click here",
            "confirm here",
            "update here",
            "scan this qr",
            "qr code",
        ],
        "It includes a link or QR prompt that could lead to a fake website.",
    ),
    (
        "prize_or_threat",
        2,
        [
            "you won",
            "claim your prize",
            "refund",
            "lawsuit",
            "arrest",
            "security alert",
            "penalty",
            "account suspended",
        ],
        "It uses fear, rewards, or threats to influence your decision.",
    ),
]

LESSON_BY_RISK = {
    "Safe": "Even safe-looking messages deserve a quick pause. The safest habit is to sign in from an official website or app instead of using links inside messages.",
    "Suspicious": "Scammers count on speed. If a message asks you to verify, pay, or fix something quickly, stop and confirm the request using a phone number or website you already trust.",
    "High Risk": "High-risk phishing often mixes urgency with a link, QR code, or login request. Never use the contact details inside the message to verify it.",
}

SAFE_SAMPLE = (
    "Hi Professor Davis,\n\n"
    "Just a quick reminder that our weekly project meeting is scheduled for tomorrow at 10:00 AM "
    "in the main conference room. I attached the syllabus draft for your review.\n\n"
    "Best,\nBrian"
)

SUSPICIOUS_SAMPLE = (
    "Hello Alice,\n\n"
    "We noticed an unusual login attempt on your account from a new device. Please review your "
    "recent activity when you have a moment.\n\n"
    "If this was not you, you may want to update your security settings.\n\n"
    "Best,\nSupport Team"
)

HIGH_RISK_SAMPLE = (
    "Dear Maria Lopez,\n\n"
    "Your university email account (maria.lopez24@email.com) will be suspended within 24 hours due "
    "to a security alert. Please scan the QR code on the attached image or click "
    "http://secure-update-portal-login.com/auth to verify your password immediately.\n\n"
    "If you do not act now, you will lose access to your classes. Call 909-555-4821 if you have "
    "questions.\n\nRegards,\nIT Helpdesk"
)


def validate_assessment(assessment: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(assessment, dict):
        raise ValueError("Assessment is not a JSON object.")

    risk_label = assessment.get("risk_label")
    if risk_label not in OUTPUT_SCHEMA["properties"]["risk_label"]["enum"]:
        raise ValueError(f"Invalid risk label: {risk_label!r}")

    top_reasons = assessment.get("top_3_reasons")
    if (
        not isinstance(top_reasons, list)
        or len(top_reasons) != 3
        or any(not isinstance(item, str) for item in top_reasons)
    ):
        raise ValueError("top_3_reasons must be a list of 3 strings.")

    action_checklist = assessment.get("action_checklist")
    if (
        not isinstance(action_checklist, list)
        or len(action_checklist) < 3
        or any(not isinstance(item, str) for item in action_checklist)
    ):
        raise ValueError("action_checklist must be a list of at least 3 strings.")

    return {
        "risk_label": risk_label,
        "top_3_reasons": top_reasons,
        "action_checklist": action_checklist,
    }


def redact_pii(text: str) -> str:
    """Redact common PII while preserving phishing context."""
    patterns = [
        (r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", "[REDACTED_SSN]"),
        (
            r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b",
            "[REDACTED_PHONE]",
        ),
        (r"\b(?:\d[ -]*?){13,16}\b", "[REDACTED_CARD]"),
        (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "[REDACTED_EMAIL]",
        ),
        (
            r"(?i)(dear|sincerely|regards|hello|hi|best|thanks|cheers)\s*,?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?",
            r"\1 [REDACTED_NAME]",
        ),
    ]

    redacted = text
    for pattern, replacement in patterns:
        redacted = re.sub(pattern, replacement, redacted)
    return redacted


def build_client() -> OpenAI:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set.")
    return OpenAI(api_key=api_key)


def analyze_with_openai(redacted_text: str, uploaded_image: Any | None) -> dict[str, Any]:
    client = build_client()
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    content: list[dict[str, Any]] = [
        {
            "type": "input_text",
            "text": (
                "Review the suspicious content below. Return plain-language guidance for an everyday "
                "user. Keep the reasons short, practical, and specific. If a QR code or image is "
                "provided, treat it as potentially suspicious content.\n\n"
                f"Redacted text input:\n{redacted_text or '[No text provided]'}"
            ),
        }
    ]

    if uploaded_image is not None:
        encoded_image = base64.b64encode(uploaded_image.getvalue()).decode("utf-8")
        mime_type = uploaded_image.type or "image/png"
        content.append(
            {
                "type": "input_image",
                "image_url": f"data:{mime_type};base64,{encoded_image}",
            }
        )

    response = client.responses.create(
        model=model,
        instructions=(
            "You are a Personal Cyber Safety Coach. Analyze suspicious text, website prompts, "
            "screenshots, or QR-style prompts for phishing or scams."
        ),
        input=[{"role": "user", "content": content}],
        text={
            "format": {
                "type": "json_schema",
                "name": "cyber_safety_assessment",
                "strict": True,
                "schema": OUTPUT_SCHEMA,
            }
        },
    )

    raw_output = getattr(response, "output_text", "") or ""
    if not raw_output:
        raise RuntimeError("The model returned an empty response.")

    parsed = json.loads(raw_output)
    return validate_assessment(parsed)


def analyze_text_demo(redacted_text: str) -> dict[str, Any]:
    text = redacted_text.lower()
    matches: list[tuple[int, str]] = []
    score = 0

    for _, weight, keywords, reason in DEMO_SIGNALS:
        if any(keyword in text for keyword in keywords):
            score += weight
            matches.append((weight, reason))

    matches.sort(reverse=True, key=lambda item: item[0])
    reasons = [reason for _, reason in matches[:3]]

    if score >= 6:
        risk_label = "High Risk"
    elif score >= 3:
        risk_label = "Suspicious"
    else:
        risk_label = "Safe"

    if len(reasons) < 3:
        fallback_reasons = [
            "The message does not show many obvious scam warning signs based on local checks.",
            "You should still verify the sender or website before sharing personal information.",
            "When in doubt, contact the company or school using an official website or phone number.",
        ]
        for reason in fallback_reasons:
            if reason not in reasons:
                reasons.append(reason)
            if len(reasons) == 3:
                break

    if risk_label == "High Risk":
        actions = [
            "Do not click the link, scan the QR code, open attachments, or reply to the message.",
            "Go directly to the official website or app by typing the address yourself, then verify whether the request is real.",
            "Report the message to your IT helpdesk, school, or organization before deleting it.",
        ]
    elif risk_label == "Suspicious":
        actions = [
            "Pause before acting and verify who sent it using a trusted phone number or official website.",
            "Do not use the contact details, links, or QR codes inside the message until you confirm they are real.",
            "Avoid sharing passwords, one-time codes, or payment details until verification is complete.",
        ]
    else:
        actions = [
            "Stay cautious and sign in through official websites or apps instead of message links whenever possible.",
            "Double-check the sender or website if anything feels off before sharing personal information.",
            "Keep avoiding requests for passwords, one-time codes, or urgent payments unless you independently verify them.",
        ]

    return {
        "risk_label": risk_label,
        "top_3_reasons": reasons,
        "action_checklist": actions,
    }


def strengthen_actions(result: dict[str, Any], redacted_text: str, source_label: str) -> dict[str, Any]:
    text = redacted_text.lower()
    actions: list[str] = []

    if "http://" in text or "https://" in text or "bit.ly" in text or "tinyurl" in text:
        actions.append("Do not use the link in the message. Type the official website into your browser instead.")
    if "qr" in text or source_label == "Image upload":
        actions.append("Do not scan any QR code or open any link shown in the image until you verify it through an official source.")
    if any(token in text for token in ["password", "passcode", "login", "sign in", "one-time code"]):
        actions.append("Do not enter your password or one-time code from this message into any page it suggests.")
    if any(token in text for token in ["payment", "gift card", "bank account", "wire transfer", "credit card"]):
        actions.append("Do not send money or payment details until you confirm the request through a trusted channel.")
    if any(token in text for token in ["school", "student", "university", "campus", "class"]):
        actions.append("Contact your school through the official student portal or IT helpdesk before taking any action.")

    for item in result["action_checklist"]:
        if item not in actions:
            actions.append(item)

    result["action_checklist"] = actions[:4]
    return result


def confidence_summary(used_demo_mode: bool, risk_label: str, has_image: bool) -> tuple[str, str]:
    if used_demo_mode and has_image:
        return (
            "Low confidence",
            "Offline mode cannot fully inspect screenshots or QR images, so the recommendation is based only on typed text and common warning signs.",
        )
    if used_demo_mode:
        return (
            "Moderate confidence",
            "Offline mode checks reliable phishing patterns such as urgency, login requests, payment requests, suspicious links, and threats.",
        )
    if risk_label == "Safe":
        return (
            "Moderate confidence",
            "The cloud model did not find strong scam signals, but safer verification habits are still recommended.",
        )
    return (
        "High confidence",
        "The cloud model found several coordinated scam signals and produced a more nuanced explanation than the offline fallback.",
    )


def render_feature_card(title: str, body: str, accent_class: str) -> None:
    st.markdown(
        f"""
        <div class="feature-card {accent_class}">
            <div class="feature-title">{title}</div>
            <div class="feature-body">{body}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_result_cards(items: list[str], title: str, card_class: str) -> None:
    st.subheader(title)
    for item in items:
        st.markdown(
            f"""
            <div class="{card_class}">
                <div class="result-card-text">{item}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_confidence_card(confidence_label: str, confidence_detail: str, used_demo_mode: bool) -> None:
    tone_class = "mode-card mode-offline" if used_demo_mode else "mode-card mode-cloud"
    st.markdown(
        f"""
        <div class="{tone_class}">
            <div class="mode-pill">{'Offline Fallback' if used_demo_mode else 'Cloud Review'}</div>
            <div class="mode-title">{confidence_label}</div>
            <div class="mode-body">{confidence_detail}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_risk_label(risk_label: str) -> None:
    style = RISK_STYLES.get(risk_label, RISK_STYLES["Suspicious"])
    st.markdown(
        f"""
        <div class="risk-banner" style="
            background:{style['bg']};
            color:{style['fg']};
            border:1px solid {style['border']};
            box-shadow:0 14px 34px rgba(15, 23, 42, 0.08);
        ">
            <div class="risk-eyebrow">Assessment Result</div>
            <div class="risk-mainline">
                <span class="risk-chip" style="background:{style['border']};"></span>
                <span>Risk Label: {risk_label}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_mode_summary(used_demo_mode: bool, has_image: bool) -> None:
    st.subheader("How This Review Was Generated")
    if used_demo_mode:
        st.warning(
            "Local Security Mode was used. The system applied reliable phishing checks without depending on cloud access."
        )
        
        if has_image:
            st.info(
            "Image support is best in cloud mode. Offline mode cannot inspect the uploaded image directly, so this result uses conservative visual safety guidance instead."
            )
    else:
        st.success(
            "Cloud analysis was used. This mode can review both pasted text and uploaded screenshots, "
            "including suspicious QR-style prompts inside images."
        )


def make_report_content(
    result: dict[str, Any],
    redacted_text: str,
    source_label: str,
    used_demo_mode: bool,
    confidence_label: str,
    confidence_detail: str,
) -> str:
    report_lines = [
        "CYBER SAFETY INCIDENT REPORT",
        f"Input Type: {source_label}",
        f"Analysis Mode: {'Local Heuristic Engine' if used_demo_mode else 'Cloud-Assisted Review'}",
        f"Risk Level: {result['risk_label']}",
        f"Confidence: {confidence_label}",
        "",
        "Confidence Notes:",
        confidence_detail,
    ]

    report_lines.extend(["", "Key Warning Signs:"])

    for reason in result["top_3_reasons"]:
        report_lines.append(f"- {reason}")

    report_lines.extend(["", "Recommended Next Steps:"])
    for item in result["action_checklist"]:
        report_lines.append(f"- {item}")

    report_lines.extend(["", "Redacted Submitted Content:", redacted_text or "[No text provided]"])
    return "\n".join(report_lines)


def main() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(circle at top left, rgba(13, 148, 136, 0.18), transparent 28%),
                radial-gradient(circle at top right, rgba(59, 130, 246, 0.16), transparent 24%),
                linear-gradient(180deg, #F3FAF9 0%, #FFFFFF 40%, #F8FAFC 100%);
            color: #0F172A;
        }
        header {visibility: hidden;}
        #MainMenu {visibility: hidden;}
        [data-testid="stSidebar"] > div:first-child {
            background: linear-gradient(180deg, #0F172A 0%, #10233F 100%);
        }
        [data-testid="stSidebar"] * {
            color: #E2E8F0;
        }
        [data-testid="stSidebar"] .stAlert {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.16);
        }
        .hero-card {
            position: relative;
            overflow: hidden;
            background: linear-gradient(135deg, #0F172A 0%, #133B5C 58%, #0D9488 100%);
            color: #F8FAFC;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 24px;
            padding: 1.8rem;
            box-shadow: 0 24px 60px rgba(15, 23, 42, 0.16);
            margin-bottom: 1rem;
        }
        .hero-card::after {
            content: "";
            position: absolute;
            width: 240px;
            height: 240px;
            right: -60px;
            top: -90px;
            background: radial-gradient(circle, rgba(255,255,255,0.24), transparent 65%);
            border-radius: 999px;
        }
        .hero-eyebrow {
            display: inline-block;
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            background: rgba(255,255,255,0.14);
            border: 1px solid rgba(255,255,255,0.16);
            border-radius: 999px;
            padding: 0.35rem 0.7rem;
            margin-bottom: 0.75rem;
        }
        .hero-heading {
            font-size: 2.35rem;
            line-height: 1.05;
            font-weight: 800;
            margin: 0 0 0.55rem 0;
            max-width: 680px;
        }
        .hero-copy {
            font-size: 1.05rem;
            line-height: 1.65;
            color: rgba(248, 250, 252, 0.9);
            max-width: 720px;
            margin: 0;
        }
        .feature-card {
            min-height: 132px;
            border-radius: 20px;
            padding: 1rem 1.05rem;
            background: rgba(255, 255, 255, 0.86);
            border: 1px solid #D9E5F2;
            box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05);
            backdrop-filter: blur(6px);
        }
        .feature-teal { border-top: 4px solid #0D9488; }
        .feature-blue { border-top: 4px solid #2563EB; }
        .feature-amber { border-top: 4px solid #F59E0B; }
        .feature-title {
            font-size: 1rem;
            font-weight: 700;
            margin-bottom: 0.4rem;
            color: #0F172A;
        }
        .feature-body {
            color: #334155;
            line-height: 1.55;
            font-size: 0.96rem;
        }
        .section-label {
            font-size: 0.82rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: #0F766E;
            font-weight: 700;
            margin-top: 0.5rem;
            margin-bottom: 0.55rem;
        }
        .input-shell {
            background: rgba(255, 255, 255, 0.82);
            border: 1px solid #D8E5EF;
            border-radius: 22px;
            padding: 1rem 1rem 0.25rem 1rem;
            box-shadow: 0 12px 30px rgba(15, 23, 42, 0.05);
            margin-bottom: 1rem;
        }
        .risk-banner {
            border-radius: 22px;
            padding: 1rem 1.1rem;
            margin: 0.75rem 0 1rem 0;
        }
        .risk-eyebrow {
            font-size: 0.82rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            opacity: 0.8;
            margin-bottom: 0.35rem;
        }
        .risk-mainline {
            display: flex;
            align-items: center;
            gap: 0.7rem;
            font-size: 1.7rem;
            font-weight: 800;
        }
        .risk-chip {
            width: 14px;
            height: 14px;
            border-radius: 999px;
            display: inline-block;
        }
        .mode-card {
            border-radius: 20px;
            padding: 1rem 1.1rem;
            margin-bottom: 0.9rem;
            border: 1px solid transparent;
        }
        .mode-cloud {
            background: linear-gradient(180deg, #ECFDF5 0%, #F8FAFC 100%);
            border-color: #86EFAC;
        }
        .mode-offline {
            background: linear-gradient(180deg, #FFF7ED 0%, #FFFBEB 100%);
            border-color: #FBBF24;
        }
        .mode-pill {
            display: inline-block;
            border-radius: 999px;
            padding: 0.28rem 0.6rem;
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            margin-bottom: 0.55rem;
            background: rgba(15, 23, 42, 0.06);
        }
        .mode-title {
            font-size: 1.08rem;
            font-weight: 700;
            color: #0F172A;
            margin-bottom: 0.32rem;
        }
        .mode-body {
            color: #334155;
            line-height: 1.55;
        }
        .reason-card, .action-card {
            border-radius: 18px;
            padding: 0.95rem 1rem;
            margin-bottom: 0.8rem;
            box-shadow: 0 10px 22px rgba(15, 23, 42, 0.05);
            border: 1px solid #E2E8F0;
            background: #FFFFFF;
        }
        .reason-card {
            border-left: 5px solid #F59E0B;
            background: linear-gradient(180deg, #FFFFFF 0%, #FFFDF7 100%);
        }
        .action-card {
            border-left: 5px solid #0D9488;
            background: linear-gradient(180deg, #FFFFFF 0%, #F7FFFD 100%);
        }
        .result-card-text {
            color: #0F172A;
            line-height: 1.58;
            font-size: 0.97rem;
        }
        .teaching-card {
            border-radius: 20px;
            padding: 1rem 1.1rem;
            background: linear-gradient(135deg, #EFF6FF 0%, #F8FAFC 100%);
            border: 1px solid #BFDBFE;
            box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05);
        }
        .report-card {
            border-radius: 20px;
            padding: 1rem 1.1rem;
            background: linear-gradient(135deg, #FAF5FF 0%, #FFFFFF 100%);
            border: 1px solid #DDD6FE;
            box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05);
        }
        @media (max-width: 900px) {
            .hero-heading {
                font-size: 1.85rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if "sample_text" not in st.session_state:
        st.session_state.sample_text = ""

    with st.sidebar:
        st.header("Why this app is safe to use")
        st.write("Your text is redacted before analysis to remove common personal details.")
        st.write("This app does not save your submissions, results, or browsing history.")
        st.write("If cloud-assisted review is unavailable, the app switches to a local safety engine that still catches common phishing patterns.")
        st.write("For best privacy, avoid pasting passwords, account numbers, or private files.")
        st.divider()
        st.subheader("What we can analyze")
        st.caption("Text, suspicious links, screenshots, and QR-style prompts.")
        st.divider()
        st.subheader("30-second safety tip")
        st.info(
            "Before clicking a link or scanning a QR code, pause and verify where it leads using an "
            "official website or app you trust."
        )

    st.markdown(
        """
        <div class="hero-card">
            <div class="hero-eyebrow">Privacy-first phishing guidance</div>
            <h1 class="hero-heading">Scam Shield</h1>
            <p class="hero-copy">
                Paste suspicious text or upload a screenshot to get a clear scam assessment,
                automatic privacy redaction, and specific next steps that everyday users can follow.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")
    st.markdown('<div class="section-label">How it works</div>', unsafe_allow_html=True)
    story_col1, story_col2, story_col3 = st.columns(3)
    with story_col1:
        render_feature_card("1. Protect privacy", "Names, emails, phone numbers, and other common PII are redacted before analysis.", "feature-teal")
    with story_col2:
        render_feature_card("2. Analyze the threat", "The system reviews content using privacy-first local heuristic rules, with optional cloud-assisted review when available.", "feature-blue")   
    with story_col3:
        render_feature_card("3. Recommend action", "Users get a simple risk label, specific next steps, and a report they can forward.", "feature-amber")

    st.write("")
    st.markdown('<div class="section-label">Scenarios</div>', unsafe_allow_html=True)
    st.write("Load a sample message to see how it works:")
    sample_col1, sample_col2, sample_col3 = st.columns(3)
    with sample_col1:
        if st.button("Load Safe Sample", use_container_width=True):
            st.session_state.sample_text = SAFE_SAMPLE
    with sample_col2:
        if st.button("Load Suspicious Sample", use_container_width=True):
            st.session_state.sample_text = SUSPICIOUS_SAMPLE
    with sample_col3:
        if st.button("Load High Risk Sample", use_container_width=True):
            st.session_state.sample_text = HIGH_RISK_SAMPLE

    st.markdown('<div class="section-label">Investigate a message</div>', unsafe_allow_html=True)
    st.markdown('<div class="input-shell">', unsafe_allow_html=True)
    user_text = st.text_area(
        "Paste email text, website text, or a suspicious URL",
        value=st.session_state.sample_text,
        height=220,
        placeholder="Example: Your account will be suspended today. Click here to verify your password...",
    )

    uploaded_image = st.file_uploader(
        "Optional: upload a screenshot or QR-style image (small PNG/JPG only)",
        type=["png", "jpg", "jpeg"],
        help="Cloud mode can review uploaded images. Offline mode cannot inspect image contents directly and uses conservative visual safety guidance instead.",
    )
    st.markdown("</div>", unsafe_allow_html=True)

    if uploaded_image is not None:
        if uploaded_image is not None and uploaded_image.size > 4 * 1024 * 1024:
            st.warning("This image is too large for cloud review. Please upload a smaller PNG/JPG screenshot.")
            return
        else:
            st.image(uploaded_image, caption="Uploaded image for review", use_container_width=True)

    analyze_clicked = st.button("Analyze", type="primary", use_container_width=True)

    if analyze_clicked:
        if not user_text.strip() and uploaded_image is None:
            st.warning("Please paste suspicious text or upload an image before running the analysis.")
            return

        redacted_text = redact_pii(user_text.strip())
        source_label = "Image upload" if uploaded_image is not None and not redacted_text else "Text and image"
        if uploaded_image is None:
            source_label = "Text input"

        with st.expander("Preview redacted text used for analysis", expanded=False):
            st.code(redacted_text or "[No text was provided.]", language="text")

        used_demo_mode = False
        try:
            with st.spinner("Reviewing the content for scam and phishing signs..."):
                result = analyze_with_openai(redacted_text, uploaded_image)
        except Exception:
            used_demo_mode = True

            # --- THE NEW ZERO-TRUST VISUAL FALLBACK ---
            if not redacted_text and uploaded_image is not None:
                st.warning(
                    "Cloud analysis unavailable. Providing baseline visual safety protocols for unverified images."
                )
                result = {
                    "risk_label": "Suspicious",
                    "top_3_reasons": [
                        "Offline mode cannot physically scan the contents of screenshots or QR codes.",
                        "Scammers frequently use images and QR codes to hide malicious links from security scanners.",
                        "Because offline mode cannot verify where image-based prompts or links lead, the content should be treated cautiously."
                    ],
                    "action_checklist": [
                        "If the image claims to be from your school, bank, or employer, contact them through their official website or phone number.",
                        "Verify the source of this message through a separate, trusted channel (like calling the sender).",
                        "Wait until you have a secure network connection to re-scan this image."
                    ]
                }
            elif not redacted_text:
                st.error("Please provide text or an image to analyze.")
                return
            else:
                # Standard text fallback
                result = analyze_text_demo(redacted_text)
                st.info(
                    "OpenAI analysis was unavailable, so this result was generated using local offline safety rules."
                )

        result = strengthen_actions(result, redacted_text, source_label)
        confidence_label, confidence_detail = confidence_summary(
            used_demo_mode=used_demo_mode,
            risk_label=result["risk_label"],
            has_image=uploaded_image is not None,
        )

        render_risk_label(result["risk_label"])
        render_confidence_card(confidence_label, confidence_detail, used_demo_mode)
        render_mode_summary(used_demo_mode, uploaded_image is not None)

        col1, col2 = st.columns(2, gap="large")

        with col1:
            render_result_cards(result["top_3_reasons"], "Top 3 Reasons", "reason-card")

        with col2:
            render_result_cards(result["action_checklist"], "Specific Next Steps", "action-card")

        st.divider()
        st.subheader("Quick Teaching Tip")
        st.markdown(
            f'<div class="teaching-card">{LESSON_BY_RISK[result["risk_label"]]}</div>',
            unsafe_allow_html=True,
        )

        st.divider()
        st.subheader("Report This Incident")
        st.markdown(
            '<div class="report-card">Generate a plain-text summary to forward to IT, a helpdesk, or a teacher.</div>',
            unsafe_allow_html=True,
        )

        report_content = make_report_content(
            result=result,
            redacted_text=redacted_text,
            source_label=source_label,
            used_demo_mode=used_demo_mode,
            confidence_label=confidence_label,
            confidence_detail=confidence_detail,
        )

        st.download_button(
            label="Download IT Report (.txt)",
            data=report_content,
            file_name="cyber_incident_report.txt",
            mime="text/plain",
        )


if __name__ == "__main__":
    main()
