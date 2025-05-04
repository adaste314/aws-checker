# 🔐 AWS Cloud Security Checklist

A Streamlit web app that connects to your AWS account and runs a series of real-time security checks using `boto3`. The app helps identify common misconfigurations in your AWS environment and provides actionable CLI fixes and AWS documentation links.

---

## 📦 Features

✅ No credentials stored  
✅ Runs  on Streamlit at https://aws-checker-ayjujxqtyv8ehzsgbdoddz.streamlit.app/  
✅ CLI fix suggestions for every failed check  
✅ AWS documentation links included  
✅ Security score summary with visual pie chart  
✅ Downloadable Markdown audit report  

---

## 🚨 What It Checks

| Category              | Check Description                                      |
|----------------------|--------------------------------------------------------|
| S3                   | Bucket encryption enabled                              |
| S3                   | Public access settings                                 |
| IAM                  | Root account MFA enabled                               |
| IAM                  | Admin privileges on users                              |
| IAM                  | Unused access keys (inactive >90 days)                 |
| CloudTrail           | Multi-region logging enabled                           |
| EC2                  | Open security groups (0.0.0.0/0)                        |
| EC2                  | Publicly attached Elastic IPs                          |

---

## 🛠️ Built With

- [Streamlit](https://streamlit.io/)
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [Matplotlib](https://matplotlib.org/)
