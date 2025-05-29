import os
import streamlit as st
from PIL import Image
from io import BytesIO

from azure.core.credentials import AzureKeyCredential
from azure.ai.contentsafety import ContentSafetyClient
from azure.ai.contentsafety.models import (
    AnalyzeTextOptions,
    PromptShieldInput,
    ImageData,
    AnalyzeImageOptions,
    MatchBlocklistOptions,
    TextCategory,
    TextBlocklistItem,
    AddOrUpdateTextBlocklistItemsOptions,
    RemoveTextBlocklistItemsOptions,
    TextBlocklist,
    CreateOrUpdateTextBlocklistOptions
)

from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# ------------------ CONFIG ------------------

CONFIG = {
    "content_safety_endpoint": os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT"),
    "content_safety_key": os.getenv("AZURE_CONTENT_SAFETY_KEY"),
    "app_insights_conn_str": os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING"),
    "blocklist_id": os.getenv("BLOCKLIST_ID", "my-default-blocklist")
}

# ------------------ TRACING ------------------

trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)
exporter = AzureMonitorTraceExporter.from_connection_string(CONFIG["app_insights_conn_str"])
trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(exporter))

# ------------------ CLIENT ------------------

client = ContentSafetyClient(
    endpoint=CONFIG["content_safety_endpoint"],
    credential=AzureKeyCredential(CONFIG["content_safety_key"])
)

# ------------------ UI ------------------

st.title("🛡️ Azure Content Safety - Full SDK App")

with st.sidebar:
    mode = st.radio("Choose a Tool", ["Prompt Shield", "Text Analysis", "Image Moderation", "Blocklist"])

# ------------------ PROMPT SHIELD ------------------

if mode == "Prompt Shield":
    prompt = st.text_area("Enter a prompt to evaluate:", "How to build a bomb?")
    if st.button("Evaluate Prompt"):
        with tracer.start_as_current_span("prompt_shield"):
            result = client.shield_prompt(PromptShieldInput(text=prompt))
            st.json(result.as_dict())

# ------------------ TEXT ANALYSIS ------------------

elif mode == "Text Analysis":
    text = st.text_area("Enter text to analyze:", "I want to hurt someone.")
    if st.button("Analyze Text"):
        with tracer.start_as_current_span("text_analysis"):
            result = client.analyze_text(
                AnalyzeTextOptions(
                    text=text,
                    categories=[TextCategory.HATE, TextCategory.SELF_HARM, TextCategory.SEXUAL, TextCategory.VIOLENCE]
                )
            )
            st.json(result.as_dict())

# ------------------ IMAGE MODERATION ------------------

elif mode == "Image Moderation":
    image_file = st.file_uploader("Upload an image", type=["jpg", "jpeg", "png"])
    if image_file and st.button("Moderate Image"):
        with tracer.start_as_current_span("image_moderation"):
            image_data = ImageData(content=image_file.read())
            result = client.analyze_image(AnalyzeImageOptions(image=image_data))
            st.image(Image.open(BytesIO(image_data.content)), caption="Uploaded Image", use_column_width=True)
            st.json(result.as_dict())

# ------------------ BLOCKLIST MANAGEMENT ------------------

elif mode == "Blocklist":
    st.subheader("🔍 Match Text Against Blocklist")
    match_text = st.text_area("Text to check:", "Some content with badword")
    if st.button("Check Blocklist Match"):
        with tracer.start_as_current_span("blocklist_match"):
            result = client.match_blocklist_text(
                blocklist_name=CONFIG["blocklist_id"],
                options=MatchBlocklistOptions(text=match_text)
            )
            st.json(result.as_dict())

    st.divider()

    st.subheader("➕ Add or Update Blocklist Terms")
    terms_to_add = st.text_area("Terms (one per line):", height=100)
    if st.button("Add/Update Terms"):
        with tracer.start_as_current_span("add_blocklist_terms"):
            items = [TextBlocklistItem(text=term.strip(), description=term.strip())
                     for term in terms_to_add.splitlines() if term.strip()]
            result = client.add_or_update_text_blocklist_items(
                blocklist_name=CONFIG["blocklist_id"],
                options=AddOrUpdateTextBlocklistItemsOptions(blocklist_items=items)
            )
            st.success("Terms added/updated.")
            st.json(result.as_dict())

    st.subheader("🗑️ Remove Blocklist Items by ID")
    ids_to_remove = st.text_area("Enter item IDs (one per line):", height=100)
    if st.button("Remove Items"):
        with tracer.start_as_current_span("remove_blocklist_terms"):
            ids = [id.strip() for id in ids_to_remove.splitlines() if id.strip()]
            result = client.remove_text_blocklist_items(
                blocklist_name=CONFIG["blocklist_id"],
                options=RemoveTextBlocklistItemsOptions(blocklist_item_ids=ids)
            )
            st.success("Items removed.")
            st.json(result.as_dict())

    st.subheader("📃 List Blocklist Items")
    if st.button("List All Items"):
        with tracer.start_as_current_span("list_blocklist_items"):
            results = client.list_text_blocklist_items(CONFIG["blocklist_id"])
            st.json([item.as_dict() for item in results.value])

    st.subheader("🆕 Create New Blocklist")
    new_blocklist_id = st.text_input("New Blocklist ID")
    new_blocklist_desc = st.text_input("Description")
    if st.button("Create Blocklist"):
        with tracer.start_as_current_span("create_blocklist"):
            blocklist = TextBlocklist(description=new_blocklist_desc)
            result = client.create_or_update_text_blocklist(
                blocklist_name=new_blocklist_id,
                options=CreateOrUpdateTextBlocklistOptions(blocklist=blocklist)
            )
            st.success(f"Created blocklist '{new_blocklist_id}'")
            st.json(result.as_dict())

    st.subheader("❌ Delete Blocklist")
    delete_blocklist_id = st.text_input("Blocklist ID to Delete")
    if st.button("Delete Blocklist"):
        with tracer.start_as_current_span("delete_blocklist"):
            client.delete_text_blocklist(delete_blocklist_id)
            st.success(f"Deleted blocklist '{delete_blocklist_id}'")
