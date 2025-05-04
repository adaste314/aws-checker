import boto3
from botocore.exceptions import ClientError

def check_s3_encryption(session):
    s3 = session.client('s3')
    results = []
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            name = bucket['Name']
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc['ServerSideEncryptionConfiguration']['Rules']
                results.append((name, True, "Encryption enabled"))
            except ClientError as e:
                results.append((name, False, "No encryption or error: " + str(e)))
    except Exception as e:
        return [("Error", False, str(e))]
    return results

def check_cloudtrail_enabled(session):
    ct = session.client('cloudtrail')
    try:
        trails = ct.describe_trails()['trailList']
        if any(t['IsMultiRegionTrail'] for t in trails):
            return ("CloudTrail", True, "CloudTrail enabled (multi-region)")
        return ("CloudTrail", False, "Only regional or no trails enabled")
    except Exception as e:
        return ("CloudTrail", False, f"Error: {str(e)}")

def check_mfa_on_root(session):
    iam = session.client('iam')
    try:
        summary = iam.get_account_summary()['SummaryMap']
        mfa = summary.get('AccountMFAEnabled', 0)
        return ("Root MFA", mfa == 1, "MFA is enabled" if mfa else "MFA is NOT enabled")
    except Exception as e:
        return ("Root MFA", False, f"Error: {str(e)}")
