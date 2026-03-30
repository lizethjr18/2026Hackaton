import json
import os
import re
from typing import Any

import streamlit as st
from openai import OpenAI


st.set_page_config(
    page_title="Cyber Safety Coach",
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
        ],
        "It includes a link or click prompt that could lead to a fake website.",
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
        ],
        "It uses fear, rewards, or threats to influence your decision.",
    ),
]


def redact_pii(text: str) -> str:
    """Redact common PII while avoiding destroying the phishing context."""
    patterns = [
        # SSNs (XXX-XX-XXXX or XXXXXXXXX)
        (
            r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
            "[REDACTED_SSN]",
        ),
        # Phone numbers
        (
            r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b",
            "[REDACTED_PHONE]",
        ),
        # Credit Card numbers
        (
            r"\b(?:\d[ -]*?){13,16}\b",
            "[REDACTED_CARD]",
        ),
        # Email addresses
        (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "[REDACTED_EMAIL]",
        ),
        # Names (Catches greetings and sign-offs, handles commas)
        (
            r"(?i)(dear|sincerely|regards|hello|hi|best|thanks|cheers)\s*[,]?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?",
            r"\1 [REDACTED_NAME]", 
        )
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


def analyze_text(redacted_text: str) -> dict[str, Any]:
    client = build_client()
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    response = client.responses.create(
        model=model,
        instructions="You are a Personal Cyber Safety Coach. Analyze this text for phishing or scams.",
        input=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "Review the message below. Return plain-language guidance for an everyday user. "
                            "Keep the reasons short and practical.\n\n"
                            f"Text to analyze:\n{redacted_text}"
                        ),
                    }
                ],
            }
        ],
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
    return {
        "risk_label": parsed["risk_label"],
        "top_3_reasons": parsed["top_3_reasons"],
        "action_checklist": parsed["action_checklist"],
    }


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
            "Do not click links, open attachments, or reply to the message.",
            "Verify the request through an official website, app, or phone number you trust.",
            "Delete or report the message if it looks fake after checking.",
        ]
    elif risk_label == "Suspicious":
        actions = [
            "Pause before acting and verify who sent it.",
            "Check the link or sender carefully using an official source, not the message itself.",
            "Avoid sharing passwords, codes, or payment details until you confirm it is real.",
        ]
    else:
        actions = [
            "Stay cautious and double-check the sender or website if anything feels off.",
            "Use official websites or apps when signing in or making payments.",
            "Keep avoiding messages that ask for passwords, one-time codes, or urgent payments.",
        ]

    return {
        "risk_label": risk_label,
        "top_3_reasons": reasons,
        "action_checklist": actions,
    }


def render_risk_label(risk_label: str) -> None:
    style = RISK_STYLES.get(risk_label, RISK_STYLES["Suspicious"])
    st.markdown(
        f"""
        <div style="
            background:{style['bg']};
            color:{style['fg']};
            border-left:8px solid {style['border']};
            border-radius:12px;
            padding:18px 20px;
            margin-bottom:12px;
            font-size:1.6rem;
            font-weight:700;
        ">
            Risk Label: {risk_label}
        </div>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(180deg, #F6FBFF 0%, #FFFFFF 45%, #F8FAFC 100%);
            color: #0F172A;
        }
        .hero-card {
            background: #ffffff;
            border: 1px solid #DCE7F2;
            border-radius: 18px;
            padding: 1.4rem;
            box-shadow: 0 12px 30px rgba(15, 23, 42, 0.06);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.header("Why this app is safe to use")
        st.write("Your text is redacted before analysis to remove common personal details.")
        st.write("This app does not save your submissions, results, or browsing history.")
        st.write("If the API is unavailable, the app can switch to a local demo mode for classroom use.")
        st.write("For best privacy, avoid pasting passwords, account numbers, or private files.")
        st.divider()
        st.caption("Tip: You can paste either an email message or a suspicious website link.")

    st.markdown(
        """
        <div class="hero-card">
            <h1 style="margin-bottom:0.25rem;">Cyber Safety Coach</h1>
            <p style="font-size:1.05rem; margin-top:0;">
                Paste a suspicious email or website link to get a simple, safety-first explanation.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    


    st.write("")
    user_text = st.text_area(
        "Paste email text or a URL",
        height=240,
        placeholder="Example: Dear customer, your package is delayed. Click here to confirm your payment details...",
    )

    analyze_clicked = st.button("Analyze", type="primary", use_container_width=True)

    if analyze_clicked:
        if not user_text.strip():
            st.warning("Please paste email text or a URL before running the analysis.")
            return

        redacted_text = redact_pii(user_text.strip())

        with st.expander("Preview redacted text sent to the AI", expanded=False):
            st.code(redacted_text, language="text")

        used_demo_mode = False
        try:
            with st.spinner("Reviewing the message for scam and phishing signs..."):
                result = analyze_text(redacted_text)
        except Exception as exc:
            used_demo_mode = True
            result = analyze_text_demo(redacted_text)
            st.info("OpenAI analysis was unavailable, so this result was generated using local demo-mode safety rules.")
            st.caption(f"Technical details: {exc}")

        render_risk_label(result["risk_label"])

        if used_demo_mode:
            st.caption("Demo mode is helpful for practice and presentations, but it is less nuanced than a live AI review.")

        col1, col2 = st.columns(2, gap="large")

        with col1:
            st.subheader("Top 3 Reasons")
            for reason in result["top_3_reasons"]:
                st.markdown(f"- {reason}")

        with col2:
            st.subheader("Action Checklist")
            for item in result["action_checklist"]:
                st.markdown(f"- {item}")


if __name__ == "__main__":
    main()
