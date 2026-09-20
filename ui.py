"""Judge-friendly Streamlit interface for the NiceTryDidi local scam checker."""

from __future__ import annotations

from typing import Any

import requests
import streamlit as st


BACKEND_URL = "http://127.0.0.1:8000/api/check-scam"
LANGUAGES = ["Hindi", "Telugu", "Tamil", "Bengali", "Marathi", "Kannada", "Gujarati"]
PRESETS = {
    "electricity": (
        "Your electricity bill is overdue. Pay immediately within 30 minutes or your connection "
        "will be disconnected today. Call this officer now."
    ),
    "cashback": (
        "Congratulations! You have won ₹2,000 UPI cashback. Accept the collect request and enter "
        "your UPI PIN to claim your money now."
    ),
    "apk": (
        "India Post: Your parcel address is incomplete. Update it now at https://indiapost-track.example/update.apk"
    ),
}


st.set_page_config(page_title="NiceTryDidi - Scam Guard", page_icon="🛡️", layout="centered")

st.markdown(
    """
    <style>
      .stApp { background: linear-gradient(160deg, #f7fbff 0%, #f8f9f2 100%); }
      .rakshak-hero {
        padding: 1.25rem 1.4rem; border-radius: 18px; color: #ffffff;
        background: linear-gradient(120deg, #092f57, #0b6b6f); margin-bottom: 1rem;
      }
      .rakshak-hero h1 { margin: 0; font-size: 2.05rem; }
      .rakshak-hero p { margin: .3rem 0 0; opacity: .92; }
      .risk-card { border-left: 5px solid #d62828; padding-left: .75rem; }
      .safe-card { border-left: 5px solid #16803c; padding-left: .75rem; }
      div.stButton > button { border-radius: 9px; font-weight: 600; }
    </style>
    <div class="rakshak-hero">
      <h1>🛡️ NiceTryDidi</h1>
      <p>Local SMS &amp; UPI Scam Guard</p>
    </div>
    """,
    unsafe_allow_html=True,
)
st.caption("Your message is analysed locally through Ollama. Never share your UPI PIN or OTP.")

language = st.selectbox("Choose your language", LANGUAGES)

st.write("**Try a judge-ready example**")
quick_cols = st.columns(3)
if quick_cols[0].button("⚡ Electricity Threat", use_container_width=True):
    st.session_state.message_text = PRESETS["electricity"]
if quick_cols[1].button("💸 Fake UPI Cashback", use_container_width=True):
    st.session_state.message_text = PRESETS["cashback"]
if quick_cols[2].button("📦 IndiaPost APK", use_container_width=True):
    st.session_state.message_text = PRESETS["apk"]

if "message_text" not in st.session_state:
    st.session_state.message_text = ""

message = st.text_area(
    "Paste an SMS, UPI request, or suspicious message",
    key="message_text",
    height=180,
    placeholder="Paste the message here…",
)


def render_actions(action: str) -> None:
    """Show one numbered safety step per line when the model follows the prompt."""
    steps = [line.strip().lstrip("•- ") for line in action.splitlines() if line.strip()]
    if len(steps) > 1:
        for step in steps:
            st.markdown(f"- {step}")
    else:
        st.markdown(action)


if st.button("🔍 Check for Scam", type="primary", use_container_width=True):
    if not message.strip():
        st.warning("Please paste a message before checking it.")
    else:
        try:
            with st.spinner("Analyzing..."):
                api_response = requests.post(
                    BACKEND_URL,
                    json={"message": message.strip(), "language": language},
                    timeout=(5, 100),
                )
            api_response.raise_for_status()
            result: dict[str, Any] = api_response.json()
        except requests.ConnectionError:
            st.error("Backend is not running. Start it with: `uvicorn app:app --host 0.0.0.0 --port 8000`")
        except requests.Timeout:
            st.error("The local model took too long to respond. Confirm Ollama is running and try again.")
        except requests.HTTPError:
            try:
                detail = api_response.json().get("detail", "The backend could not analyse this message.")
            except ValueError:
                detail = "The backend could not analyse this message."
            st.error(str(detail))
        except (ValueError, requests.RequestException):
            st.error("Could not read the backend response. Please try again.")
        else:
            st.divider()
            if result.get("is_scam") is True:
                scam_type = result.get("scam_type", "Suspicious message")
                confidence = result.get("confidence", "Unknown")
                st.error(f"🚨 SCAM DETECTED  •  {confidence} confidence  •  {scam_type}")

                call_col, report_col = st.columns(2)
                call_col.link_button("📞 Call 1930 Cyber Helpline", "tel:1930", use_container_width=True)
                report_col.link_button(
                    "🔗 Report to Cybercrime.gov.in",
                    "https://cybercrime.gov.in",
                    use_container_width=True,
                )
            else:
                st.success("✅ LIKELY SAFE")
                st.caption("This is an automated assessment; remain cautious if the sender is unknown.")

            for warning in result.get("regex_warnings", []):
                st.warning(f"⚠️ {warning}")

            st.subheader(f"🗣️ Verdict in {language}")
            st.info(result.get("verdict_regional", "No regional verdict was returned."))
            st.subheader(f"🧭 What to do ({language})")
            render_actions(str(result.get("action_regional", "Stay cautious and verify through official channels.")))

            with st.expander("Show English Details"):
                st.write(result.get("verdict_english", "No English verdict was returned."))
                st.markdown("**Recommended actions**")
                render_actions(str(result.get("action_english", "Stay cautious and verify through official channels.")))
