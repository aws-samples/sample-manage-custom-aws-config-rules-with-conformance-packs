# Manage Custom AWS Config Rules with Conformance Packs

This project provides a solution for managing custom AWS Config rules and automating security group compliance using AWS Conformance Packs. It includes Lambda functions, IAM roles, and SSM automation to evaluate and remediate security group configurations across AWS accounts.

## Features

- **Custom AWS Config Rules**: Implements a rule to check if security group rules allow access for CIDR blocks larger than `/16`.
- **Automated Remediation**: Uses Lambda functions and SSM automation to revoke non-compliant security group rules.
- **Cross-Account Access**: Supports cross-account compliance checks using IAM roles.
- **CloudFormation Templates**: Includes templates for deploying resources in both management and member accounts.

## Folder Structure

- **`AutomationSecurityGroupConformanceLambdaFunction.py`**: Lambda function for remediating non-compliant security group rules.
- **`ConformancePackSecurityGroupLambdaFunction.py`**: Lambda function for evaluating security group compliance.
- **`management-cfn.yml`**: CloudFormation template for deploying resources in the management account.
- **`member-account-cfn.yml`**: CloudFormation template for deploying IAM roles in member accounts.
  - Deploys an IAM role (`member-acc-role`) that allows the management account to assume the role and perform compliance checks.
  - Includes permissions for AWS Config, EC2, and CloudWatch Logs.
- **`cpack.yml`**: Conformance pack configuration for AWS Config rules and remediation.
- **`README.md`**: Documentation for the project.

## Deployment

### Prerequisites

1. AWS CLI installed and configured.
2. Permissions to deploy CloudFormation stacks in both management and member accounts.
3. Python 3.8 runtime for Lambda functions.

### Steps

1. **Deploy Member Account Resources**:
   - Use `member-account-cfn.yml` to deploy the IAM role in member accounts.
   - Example command:
     ```bash
     aws cloudformation deploy --template-file member-account-cfn.yml --stack-name MemberAccountStack --parameter-overrides ManagementAccountID=<ManagementAccountID>
     ```

2. **Deploy Management Account Resources**:
   - Use `management-cfn.yml` to deploy Lambda functions, IAM roles, and SSM automation in the management account.
   - Example command:
     ```bash
     aws cloudformation deploy --template-file management-cfn.yml --stack-name ManagementAccountStack --parameter-overrides ManagementAccountId=<ManagementAccountID>
     ```

3. **Deploy Conformance Pack**:
   - Use `cpack.yml` to deploy the AWS Config rule and remediation configuration.
   - Example command:
     ```bash
     aws configservice put-conformance-pack --conformance-pack-name SecurityGroupConformancePack --template-body file://cpack.yml
     ```

## Usage

- **Compliance Evaluation**:
  - The `ConformancePackSecurityGroupLambdaFunction` evaluates security group compliance based on CIDR rules.
- **Remediation**:
  - The `AutomationSecurityGroupConformanceLambdaFunction` revokes non-compliant security group rules automatically.

## Architecture

1. **Management Account**:
   - Hosts the Lambda functions, IAM roles, and SSM automation.
   - Evaluates and remediates security group compliance across member accounts.

2. **Member Accounts**:
   - Contains IAM roles that allow the management account to assume roles and perform compliance checks.

## Security

- The solution uses least-privilege IAM roles to ensure secure cross-account access.
- All actions are logged in AWS CloudTrail for auditing purposes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.