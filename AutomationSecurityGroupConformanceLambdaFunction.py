"""
AWS Lambda function for managing security group rules compliance.
This module handles the evaluation and remediation of non-compliant security group rules.
"""
import boto3
import logging
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_temporary_credentials(account_id):
    """Get temporary credentials for cross-account access."""
    try:
        sts_client = boto3.client('sts')
        role_arn = f'arn:aws:iam::{account_id}:role/member-acc-role'
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="cross_acct_lambda",
            DurationSeconds=900  # 15 minutes
        )
        return response['Credentials']
    except ClientError as e:
        logger.warning(f"Failed to assume role: {str(e)}")
        raise

def get_ec2_client(credentials):
    """Initialize EC2 client with temporary credentials."""
    return boto3.client(
        'ec2',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

def get_security_group_rules(ec2_client, security_group_id):
    """Retrieve security group rules."""
    try:
        response = ec2_client.describe_security_groups(GroupIds=[security_group_id])
        return response['SecurityGroups'][0].get('IpPermissions', [])
    except ClientError as e:
        logger.warning(f"Failed to describe security group {security_group_id}: {str(e)}")
        raise

def is_rule_compliant(cidr_block):
    """
    Check if CIDR block complies with security requirements.
    Valid CIDR blocks should have prefix length of 0 or >= 16
    """
    try:
        prefix_len = int(cidr_block.split('/')[1])
        return prefix_len >= 16
    except ValueError:
        logger.error(f"Invalid CIDR block format: {cidr_block}")
        return False


def revoke_non_compliant_rules(ec2_client, security_group_id, rules):
    """Revoke non-compliant security group rules."""
    rules_revoked = 0
    for rule in rules:
        if not rule.get('UserIdGroupPairs'):
            for ip_range in rule.get('IpRanges', []):
                cidr_block = ip_range['CidrIp']
                if not is_rule_compliant(cidr_block):
                    try:
                        ec2_client.revoke_security_group_ingress(
                            GroupId=security_group_id,
                            IpPermissions=[rule]
                        )
                        rules_revoked += 1
                        logger.info(f"Revoked non-compliant rule: {cidr_block}")
                    except ClientError as e:
                        logger.error(f"Failed to revoke rule: {str(e)}")
    return rules_revoked

def lambda_handler(event, context):
    """Main Lambda handler function."""
    try:
        logger.info(f"Processing event: {event}")

        # Extract required parameters
        security_group_id = event.get('parameterValue')
        account_id = event.get('accountID')

        # Validate input parameters
        if not all([security_group_id, account_id]):
            raise ValueError("Missing required parameters")

        # Get temporary credentials and initialize EC2 client
        credentials = get_temporary_credentials(account_id)
        ec2_client = get_ec2_client(credentials)

        # Get security group rules
        rules = get_security_group_rules(ec2_client, security_group_id)

        # Revoke non-compliant rules
        rules_revoked = revoke_non_compliant_rules(ec2_client, security_group_id, rules)

        # Return success response
        return {
            'statusCode': 200,
            'body': {
                'message': 'Successfully processed security group rules',
                'securityGroupId': security_group_id,
                'rulesProcessed': len(rules),
                'rulesRevoked': rules_revoked
            }
        }

    except ValueError as e:
        # Handle validation errors
        logger.error(f"Validation error: {str(e)}")
        return {'statusCode': 400, 'body': {'error': str(e)}}
    except ClientError as e:
        # Handle AWS API errors
        logger.error(f"AWS API error: {str(e)}")
        return {'statusCode': 500, 'body': {'error': str(e)}}
    except Exception as e:
        # Handle unexpected errors
        logger.error(f"Unexpected error: {str(e)}")
        return {'statusCode': 500, 'body': {'error': 'Internal server error'}}