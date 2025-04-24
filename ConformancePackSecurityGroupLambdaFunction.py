import boto3
import json
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
		"""
		Main handler for the Lambda function.
		Evaluates security group compliance based on CIDR rules.
		"""
		logger.info(f'Received event: {json.dumps(event)}')

		try:
				# Extract resource details from the event
				invoking_event = json.loads(event['invokingEvent'])
				config_item = invoking_event['configurationItem']
				
				resource_type = config_item['resourceType']
				resource_id = config_item['resourceId']
				resource_name = config_item['resourceName']
				ip_permissions = config_item['configuration']['ipPermissions']
				account_id = config_item['configuration']['ownerId']

				logger.info(f'Evaluating resource: {resource_id} ({resource_name})')

				# Get temporary credentials for the member account
				ak, sk, st = get_temp_credentials(account_id)

				# Initialize AWS Config client
				config_client = boto3.client('config',
																		aws_access_key_id=ak,
																		aws_secret_access_key=sk,
																		aws_session_token=st)

				# Determine compliance status
				if resource_type == 'AWS::EC2::SecurityGroup' and has_compliant_cidr_rule(resource_id, ip_permissions):
						compliance_type = 'COMPLIANT'
				else:
						compliance_type = 'NON_COMPLIANT'

				# Put evaluation results
				put_evaluation_results(config_client, resource_type, resource_id, resource_name, 
															compliance_type, invoking_event['notificationCreationTime'], 
															event['resultToken'])

		except Exception as e:
				logger.error(f'Error occurred: {str(e)}')
				raise

def has_compliant_cidr_rule(security_group_id, ip_permissions):
		"""
		Check if the security group has compliant CIDR rules.
		"""
		if not ip_permissions:
				return True

		for rule in ip_permissions:
				user_id_group_pairs = rule.get('userIdGroupPairs', [])
				logger.debug(f'Checking rule for security group: {security_group_id}')
				logger.debug(f'IP Permissions: {ip_permissions}, User ID Group Pairs: {user_id_group_pairs}')

				if not user_id_group_pairs:
						for ip_range in rule.get('ipRanges', []):
								cidr_block = ip_range['cidrIp']
								if '/' in cidr_block:
										prefix_len = int(cidr_block.split('/')[1])
										if prefix_len >= 16:
												return True
										else:
												return False
				else:
						return True

		return False

def get_temp_credentials(account_id):
		"""
		Get temporary credentials for the specified account.
		"""
		sts_connection = boto3.client('sts')
		role_arn = f'arn:aws:iam::{account_id}:role/member-acc-role'
		assumed_role = sts_connection.assume_role(
				RoleArn=role_arn,
				RoleSessionName="cross_acct_lambda"
		)
		credentials = assumed_role['Credentials']
		
		return (credentials['AccessKeyId'], 
						credentials['SecretAccessKey'], 
						credentials['SessionToken'])

def put_evaluation_results(config_client, resource_type, resource_id, resource_name, 
													compliance_type, notification_creation_time, result_token):
		"""
		Put evaluation results for the Config rule.
		"""
		config_client.put_evaluations(
				Evaluations=[
						{
								'ComplianceResourceType': resource_type,
								'ComplianceResourceId': resource_id,
								'ComplianceType': compliance_type,
								'Annotation': f'This resource is {compliance_type}. Security Group name: {resource_name}',
								'OrderingTimestamp': notification_creation_time
						},
				],
				ResultToken=result_token
		)
		logger.info(f'Evaluation result sent: {compliance_type} for {resource_id}')