import streamlit as st
import boto3
from aws_audit import (
    check_s3_encryption,
    check_cloudtrail_enabled,
    check_mfa_on_root,
    check_s3_public_access,
    check_iam_admin_users,
    check_open_security_groups
)
from botocore.exceptions import ClientError

st.set_page_config(page_title="AWS Cloud Security Checklist", layout="centered")

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

        total_score = 0
        max_score = 45  # 10 pts per check

        st.header("📦 S3 Bucket Encryption (10 pts)")
        s3_results = check_s3_encryption(session)
        for name, status, msg in s3_results:
            st.write(f"**{name}**: {'✅' if status else '❌'} — {msg}")
            if status:
                total_score += 3  # partial points per encrypted bucket

        st.header("📜 CloudTrail Logging (10 pts)")
        name, status, msg = check_cloudtrail_enabled(session)
        st.write(f"**{name}**: {'✅' if status else '❌'} — {msg}")
        if status:
            total_score += 10

        st.header("🔐 MFA on Root Account (10 pts)")
        name, status, msg = check_mfa_on_root(session)
        st.write(f"**{name}**: {'✅' if status else '❌'} — {msg}")
        if status:
            total_score += 10

                st.header("🌐 Public S3 Access")
        for name, status, msg in check_s3_public_access(session):
            st.write(f"**{name}**: {'✅' if status else '❌'} — {msg}")
            if status:
                total_score += 3  # Adjust weight per item

        st.header("👤 IAM Users with Admin Access")
        for name, status, msg in check_iam_admin_users(session):
            st.write(f"**{name}**: {'✅' if status else '❌'} — {msg}")
            if status:
                total_score += 3

        st.header("🛡️ Security Groups Open to the World")
        for name, status, msg in check_open_security_groups(session):
            st.write(f"**{name}**: {'✅' if status else '❌'} — {msg}")
            if status:
                total_score += 3

        # Calculate risk level
        percent = (total_score / max_score) * 100
        st.subheader("📊 Security Score Summary")
        st.write(f"**Score:** {total_score}/{max_score} ({percent:.0f}%)")

        if percent >= 80:
            st.success("🟢 Low Risk — Your AWS setup looks strong!")
        elif percent >= 50:
            st.warning("🟡 Moderate Risk — Some issues need fixing.")
        else:
            st.error("🔴 High Risk — Several security gaps found.")

    except ClientError as e:
        st.error(f"Connection error: {e}")


