import os
import json
import uuid
import base64
import hmac
import hashlib
import requests
import streamlit as st
from datetime import datetime

# ENV VARIABLES (configure before running or use st.secrets)
CONTENT_SAFETY_KEY = os.getenv("CONTENT_SAFETY_KEY")
CONTENT_SAFETY_ENDPOINT = os.getenv("CONTENT_SAFETY_ENDPOINT")
LOG_WORKSPACE_ID = os.getenv("LOG_WORKSPACE_ID")
LOG_SHARED_KEY = os.getenv("LOG_SHARED_KEY")
LOG_CUSTOM_TABLE = os.getenv("LOG_CUSTOM_TABLE", "ContentSafety_CL")
API_VERSION = "2024-02-15-preview"

# Log to Azure Monitor Logs
def send_log(log):
    body = json.dumps([log])
    time = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    string_to_hash = f"POST\n{len(body)}\napplication/json\nx-ms-date:{time}\n/api/logs"
    signature = base64.b64encode(
        hmac.new(base64.b64decode(LOG_SHARED_KEY), string_to_hash.encode(), hashlib.sha256).digest()
    ).decode()
    uri = f"https://{LOG_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        "Content-Type": "application/json",
        "Log-Type": LOG_CUSTOM_TABLE,
        "x-ms-date": time,
        "Authorization": f"SharedKey {LOG_WORKSPACE_ID}:{signature}"
    }
    requests.post(uri, headers=headers, data=body)

# Azure Content Safety POST request
def content_safety_post(path, payload, params=None):
    headers = {
        "Ocp-Apim-Subscription-Key": CONTENT_SAFETY_KEY,
        "Content-Type": "application/json"
    }
    url = f"{CONTENT_SAFETY_ENDPOINT}{path}"
    res = requests.post(url, headers=headers, json=payload, params=params)
    res.raise_for_status()
    return res.json()

# UI Layout
st.title("🔐 Azure Content Safety - Prompt & Completion Tester")

with st.form("input_form"):
    prompt = st.text_area("User Prompt", height=100)
    completion = st.text_area("Model Completion (optional)", height=100)
    blocklist_names = st.text_input("Blocklist Names (comma-separated)", value="TestBlocklist")
    submit = st.form_submit_button("Analyze")

if submit:
    try:
        # Analyze prompt using Prompt Shield
        prompt_result = content_safety_post(
            "/contentsafety/text:shieldPrompt",
            {"userPrompt": prompt},
            params={"api-version": API_VERSION}
        )

        # Analyze text + blocklist
        analysis_result = content_safety_post(
            "/contentsafety/text:analyze",
            {
                "text": prompt + " " + completion,
                "blocklistNames": [b.strip() for b in blocklist_names.split(",") if b.strip()]
            },
            params={"api-version": "2023-10-01-preview"}
        )

        st.success("✅ Analysis complete.")
        st.subheader("🧠 Prompt Shield Result")
        st.json(prompt_result)

        st.subheader("📊 Content Analysis Result")
        st.json(analysis_result)

        # Log to Azure Monitor
        send_log({
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "type": "PromptTest",
            "prompt": prompt,
            "completion": completion,
            "promptShieldResult": prompt_result,
            "contentAnalysis": analysis_result
        })

    except Exception as e:
        st.error(f"❌ Error: {e}")
