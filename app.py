import streamlit as st
import boto3
import os
import matplotlib.pyplot as plt
from io import StringIO
from datetime import datetime
from botocore.exceptions import ClientError
from aws_audit import (
    check_s3_encryption,
    check_cloudtrail_enabled,
    check_mfa_on_root,
    check_s3_public_access,
    check_iam_admin_users,
    check_open_security_groups
)

st.set_page_config(page_title="AWS Cloud Security Checklist", layout="centered")
st.title("🔐 AWS Cloud Security Checklist")

access_key = os.getenv("AWS_ACCESS_KEY_ID")
secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

with st.form("aws_credentials"):
    input_access_key = st.text_input("Access Key ID", value=access_key if access_key else "")
    input_secret_key = st.text_input("Secret Access Key", type="password", value=secret_key if secret_key else "")
    input_region = st.text_input("AWS Region", value=region)
    submitted = st.form_submit_button("Run Audit")

if submitted:
    try:
        session = boto3.Session(
            aws_access_key_id=input_access_key,
            aws_secret_access_key=input_secret_key,
            region_name=input_region
        )
        st.success("✅ Connected to AWS")

        total_score = 0
        max_score = 45
        passed, failed = 0, 0
        report_lines = [f"# AWS Security Audit Report\n", f"**Scan Time**: {datetime.utcnow()} UTC\n\n"]

        def display_check(title, results, points, total_score, passed, failed, report_lines):
            st.header(title)
            for name, status, msg, fix, link in results:
                st.write(f"**{name}**: {'✅' if status else '❌'} — {msg}")
                if status:
                    total_score += points
                    passed += 1
                else:
                    failed += 1
                    report_lines.append(f"## {name}\n❌ {msg}\n\n**Fix**: {fix}\n[Read More]({link})\n")
            return total_score, passed, failed, report_lines

        total_score, passed, failed, report_lines = display_check(
            "1️⃣ S3 Bucket Encryption", check_s3_encryption(session), 3, total_score, passed, failed, report_lines)

        total_score, passed, failed, report_lines = display_check(
            "2️⃣ CloudTrail Logging", [check_cloudtrail_enabled(session)], 10, total_score, passed, failed, report_lines)

        total_score, passed, failed, report_lines = display_check(
            "3️⃣ MFA on Root Account", [check_mfa_on_root(session)], 10, total_score, passed, failed, report_lines)

        total_score, passed, failed, report_lines = display_check(
            "4️⃣ Public S3 Access", check_s3_public_access(session), 3, total_score, passed, failed, report_lines)

        total_score, passed, failed, report_lines = display_check(
            "5️⃣ IAM Users with Admin Access", check_iam_admin_users(session), 3, total_score, passed, failed, report_lines)

        total_score, passed, failed, report_lines = display_check(
            "6️⃣ Security Groups Open to the World", check_open_security_groups(session), 3, total_score, passed, failed, report_lines)

        percent = (total_score / max_score) * 100
        st.subheader("📊 Security Score Summary")
        st.write(f"**Score:** {total_score}/{max_score} ({percent:.0f}%)")

        if percent >= 80:
            st.success("🟢 Low Risk — Your AWS setup looks strong!")
        elif percent >= 50:
            st.warning("🟡 Moderate Risk — Some issues need fixing.")
        else:
            st.error("🔴 High Risk — Several security gaps found.")

        # Pie chart
        fig, ax = plt.subplots()
        ax.pie([passed, failed], labels=['✅ Secure', '❌ Issues'], autopct='%1.1f%%', startangle=90, colors=['green', 'red'])
        ax.axis('equal')
        st.pyplot(fig)

        # Report download
        report_str = "\n".join(report_lines)
        st.download_button("📥 Download Audit Report", report_str, file_name="aws_audit.md")

    except ClientError as e:
        st.error(f"Connection error: {e}")
