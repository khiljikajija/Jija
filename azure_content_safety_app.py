import os
import streamlit as st
from azure.core.credentials import AzureKeyCredential
from azure.ai.contentsafety import ContentSafetyClient
from azure.ai.contentsafety.models import (
    AnalyzeTextOptions,
    AnalyzeImageOptions,
    TextBlocklistItem,
    AddOrUpdateTextBlocklistItemsOptions,
    RemoveTextBlocklistItemsOptions,
)
from azure.ai.resources.chat import ChatClient
from azure.ai.resources.chat.models import ChatMessage, ChatRequest

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter

AZURE_CONTENT_SAFETY_ENDPOINT = os.environ["AZURE_CONTENT_SAFETY_ENDPOINT"]
AZURE_CONTENT_SAFETY_KEY = os.environ["AZURE_CONTENT_SAFETY_KEY"]
AZURE_FOUNDRY_ENDPOINT = os.environ["AZURE_FOUNDRY_ENDPOINT"]
AZURE_FOUNDRY_API_KEY = os.environ["AZURE_FOUNDRY_API_KEY"]
AZURE_FOUNDRY_DEPLOYMENT_NAME = os.environ["AZURE_FOUNDRY_DEPLOYMENT_NAME"]
APPINSIGHTS_CONNECTION_STRING = os.environ["APPINSIGHTS_INSTRUMENTATIONKEY"]

resource = Resource(attributes={"service.name": "azure-content-safety-ui"})
trace.set_tracer_provider(TracerProvider(resource=resource))
trace.get_tracer_provider().add_span_processor(
    BatchSpanProcessor(AzureMonitorTraceExporter.from_connection_string(APPINSIGHTS_CONNECTION_STRING))
)
tracer = trace.get_tracer(__name__)

contentsafety_client = ContentSafetyClient(
    endpoint=AZURE_CONTENT_SAFETY_ENDPOINT,
    credential=AzureKeyCredential(AZURE_CONTENT_SAFETY_KEY),
)

chat_client = ChatClient(
    endpoint=AZURE_FOUNDRY_ENDPOINT,
    credential=AzureKeyCredential(AZURE_FOUNDRY_API_KEY)
)

st.title("Azure Content Safety + AI Foundry Testing")

option = st.sidebar.selectbox("Choose a test", [
    "Text Moderation",
    "Image Moderation",
    "Prompt Shield (text)",
    "Groundedness Check",
    "Blocklist Management",
    "LLM Completion (AI Foundry)"
])

if option == "Text Moderation":
    input_text = st.text_area("Enter text to analyze")
    if st.button("Analyze Text"):
        with tracer.start_as_current_span("analyze_text"):
            result = contentsafety_client.analyze_text({"text": input_text})
            st.json(result.as_dict())

elif option == "Image Moderation":
    uploaded_file = st.file_uploader("Upload image for moderation", type=["jpg", "png"])
    if uploaded_file and st.button("Analyze Image"):
        with tracer.start_as_current_span("analyze_image"):
            result = contentsafety_client.analyze_image({
                "image": uploaded_file.getvalue()
            })
            st.json(result.as_dict())

elif option == "Prompt Shield (text)":
    prompt = st.text_area("Enter user prompt")
    if st.button("Analyze Prompt"):
        with tracer.start_as_current_span("prompt_shield"):
            result = contentsafety_client.analyze_prompt({"prompt": prompt})
            st.json(result.as_dict())

elif option == "Groundedness Check":
    input_text = st.text_area("Enter output to check grounding")
    if st.button("Check Groundedness"):
        with tracer.start_as_current_span("groundedness_check"):
            result = contentsafety_client.analyze_groundedness({"output": input_text})
            st.json(result.as_dict())

elif option == "Blocklist Management":
    action = st.radio("Choose Action", ["Add Words", "Remove Words"])
    blocklist_id = st.text_input("Enter Blocklist ID", value="my-blocklist")
    words = st.text_area("Enter comma-separated blocklist words")

    if action == "Add Words" and st.button("Add to Blocklist"):
        items = [TextBlocklistItem(text=w.strip()) for w in words.split(",")]
        opts = AddOrUpdateTextBlocklistItemsOptions(items=items)
        with tracer.start_as_current_span("add_blocklist_items"):
            result = contentsafety_client.add_or_update_text_blocklist_items(
                blocklist_id=blocklist_id,
                options=opts
            )
            st.success("Words added.")
            st.json(result.as_dict())

    elif action == "Remove Words" and st.button("Remove from Blocklist"):
        opts = RemoveTextBlocklistItemsOptions(texts=[w.strip() for w in words.split(",")])
        with tracer.start_as_current_span("remove_blocklist_items"):
            result = contentsafety_client.remove_text_blocklist_items(
                blocklist_id=blocklist_id,
                options=opts
            )
            st.success("Words removed.")
            st.json(result.as_dict())

elif option == "LLM Completion (AI Foundry)":
    system = st.text_input("System prompt", value="You are an assistant.")
    user_input = st.text_area("User prompt")
    if st.button("Call Foundry LLM"):
        with tracer.start_as_current_span("llm_completion"):
            chat_request = ChatRequest(
                deployment=AZURE_FOUNDRY_DEPLOYMENT_NAME,
                messages=[
                    ChatMessage(role="system", content=system),
                    ChatMessage(role="user", content=user_input),
                ]
            )
            completion = chat_client.complete_chat(chat_request)
            st.subheader("LLM Response")
            st.write(completion.choices[0].message.content)
            tracer.current_span().set_attribute("prompt", user_input)
            tracer.current_span().set_attribute("completion", completion.choices[0].message.content)
