import streamlit as st
import boto3
from aws_audit import check_s3_encryption, check_cloudtrail_enabled, check_mfa_on_root
from botocore.exceptions import ClientError

st.set_page_config(page_title="AWS Cloud Security Audit", layout="centered")

st.title("🔐 AWS Cloud Security Checklist")

with st.form("aws_credentials"):
    access_key = st.text_input("Access Key ID")
    secret_key = st.text_input("Secret Access Key", type="password")
    region = st.text_input("AWS Region (e.g., us-east-1)", value="us-east-1")
    submitted = st.form_submit_button("Run Audit")

if submitted:
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        st.success("✅ Connected to AWS")

        st.header("1️⃣ S3 Bucket Encryption")
        for name, status, msg in check_s3_encryption(session):
            st.write(f"**{name}**: {'✅' if status else '❌'} — {msg}")

        st.header("2️⃣ CloudTrail Logging")
        name, status, msg = check_cloudtrail_enabled(session)
        st.write(f"**{name}**: {'✅' if status else '❌'} — {msg}")

        st.header("3️⃣ MFA on Root Account")
        name, status, msg = check_mfa_on_root(session)
        st.write(f"**{name}**: {'✅' if status else '❌'} — {msg}")

    except ClientError as e:
        st.error(f"Connection error: {e}")
