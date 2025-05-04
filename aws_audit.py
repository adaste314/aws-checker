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

def check_s3_public_access(session):
    s3 = session.client('s3')
    results = []
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            name = bucket['Name']
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                grants = acl.get('Grants', [])
                public = any(
                    grant['Grantee'].get('URI', '') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                    for grant in grants
                )
                results.append((name, not public, "Not public" if not public else "Publicly accessible"))
            except Exception as e:
                results.append((name, False, f"Error: {e}"))
    except Exception as e:
        return [("Error", False, str(e))]
    return results

def check_iam_admin_users(session):
    iam = session.client('iam')
    results = []
    try:
        users = iam.list_users()['Users']
        for user in users:
            policies = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            is_admin = any("AdministratorAccess" in p['PolicyName'] for p in policies)
            results.append((user['UserName'], not is_admin, "Least privilege" if not is_admin else "Admin access"))
    except Exception as e:
        return [("Error", False, str(e))]
    return results

def check_open_security_groups(session):
    ec2 = session.client('ec2')
    results = []
    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            open_ingress = False
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        open_ingress = True
            results.append((sg['GroupName'], not open_ingress,
                            "Restricted" if not open_ingress else "Open to the world"))
    except Exception as e:
        return [("Error", False, str(e))]
    return results
