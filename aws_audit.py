from botocore.exceptions import ClientError
from datetime import datetime, timezone

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
                results.append((name, True, "Encryption enabled", "", "", ""))
            except ClientError:
                results.append((
                    name,
                    False,
                    "No encryption",
                    "Enable server-side encryption for this bucket.",
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html",
                    f"aws s3api put-bucket-encryption --bucket {name} --server-side-encryption-configuration '{{...}}'"
                ))
    except Exception as e:
        results.append(("Error", False, str(e), "", "", ""))
    return results

def check_cloudtrail_enabled(session):
    ct = session.client('cloudtrail')
    try:
        trails = ct.describe_trails()['trailList']
        if any(t['IsMultiRegionTrail'] for t in trails):
            return ("CloudTrail", True, "Enabled", "", "", "")
        return (
            "CloudTrail",
            False,
            "No multi-region CloudTrail enabled",
            "Enable CloudTrail logging.",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
            "aws cloudtrail create-trail --name myTrail --is-multi-region-trail"
        )
    except Exception as e:
        return ("CloudTrail", False, str(e), "", "", "")

def check_mfa_on_root(session):
    iam = session.client('iam')
    try:
        summary = iam.get_account_summary()['SummaryMap']
        mfa = summary.get('AccountMFAEnabled', 0)
        if mfa:
            return ("Root MFA", True, "MFA enabled", "", "", "")
        else:
            return (
                "Root MFA",
                False,
                "MFA is NOT enabled on root account",
                "Enable MFA on the root account.",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html",
                "aws iam enable-mfa-device ..."
            )
    except Exception as e:
        return ("Root MFA", False, str(e), "", "", "")

def check_s3_public_access(session):
    s3 = session.client('s3')
    results = []
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            name = bucket['Name']
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                public = any(
                    grant['Grantee'].get('URI', '') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                    for grant in acl.get('Grants', [])
                )
                results.append((
                    name,
                    not public,
                    "Not public" if not public else "Publicly accessible",
                    "Block public access to this bucket.",
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                    f"aws s3api put-bucket-acl --bucket {name} --acl private"
                ))
            except Exception as e:
                results.append((name, False, f"Error: {e}", "", "", ""))
    except Exception as e:
        results.append(("Error", False, str(e), "", "", ""))
    return results

def check_iam_admin_users(session):
    iam = session.client('iam')
    results = []
    try:
        users = iam.list_users()['Users']
        for user in users:
            policies = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            is_admin = any("AdministratorAccess" in p['PolicyName'] for p in policies)
            results.append((
                user['UserName'],
                not is_admin,
                "Least privilege" if not is_admin else "Has Admin access",
                "Remove unnecessary admin access.",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage-attach-detach.html",
                f"aws iam detach-user-policy --user-name {user['UserName']} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
            ))
    except Exception as e:
        results.append(("Error", False, str(e), "", "", ""))
    return results

def check_open_security_groups(session):
    ec2 = session.client('ec2')
    results = []
    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            open_ingress = any(
                ip.get('CidrIp') == '0.0.0.0/0'
                for rule in sg.get('IpPermissions', [])
                for ip in rule.get('IpRanges', [])
            )
            results.append((
                sg['GroupName'],
                not open_ingress,
                "Restricted" if not open_ingress else "Open to the world",
                "Restrict 0.0.0.0/0 access in security group rules.",
                "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
                f"aws ec2 revoke-security-group-ingress --group-name \"{sg['GroupName']}\" --protocol all --cidr 0.0.0.0/0"
            ))
    except Exception as e:
        results.append(("Error", False, str(e), "", "", ""))
    return results

def check_unused_iam_keys(session):
    iam = session.client('iam')
    results = []
    try:
        users = iam.list_users()['Users']
        for user in users:
            keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in keys:
                last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                last = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                if last:
                    days = (datetime.now(timezone.utc) - last).days
                    if days > 90:
                        results.append((
                            f"{user['UserName']} ({key['AccessKeyId']})",
                            False,
                            f"Key unused for {days} days",
                            "Rotate or delete unused access keys.",
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
                            f"aws iam delete-access-key --user-name {user['UserName']} --access-key-id {key['AccessKeyId']}"
                        ))
    except Exception as e:
        results.append(("Error", False, str(e), "", "", ""))
    return results

def check_public_eips(session):
    ec2 = session.client('ec2')
    results = []
    try:
        addresses = ec2.describe_addresses()['Addresses']
        for addr in addresses:
            results.append((
                addr['PublicIp'],
                False,
                "EIP publicly attached",
                "Avoid unused or exposed EIPs.",
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html",
                f"aws ec2 release-address --allocation-id {addr['AllocationId']}"
            ))
    except Exception as e:
        results.append(("Error", False, str(e), "", "", ""))
    return results
