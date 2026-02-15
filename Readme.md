# PawPatrol - AWS IAM Policy Validation Solution

An AWS-native solution that monitors and validates IAM policy changes in real-time using serverless architecture.

## Architecture Overview

The solution automatically triggers validation whenever an IAM policy is added or changed:

1. **AWS CloudTrail** - Captures all IAM API calls
2. **Amazon EventBridge** - Filters IAM policy change events
3. **Lambda Orchestrator** - Retrieves policy details and attachments
4. **Lambda Validator** - Validates policy against compliance rules
5. **Amazon DynamoDB** - Tracks validation attempts and results
6. **Amazon SNS** - Sends alerts on validation failures

## Monitored Events

The solution monitors the following IAM events:
- `CreatePolicy` - New managed policy creation
- `CreatePolicyVersion` - New version of managed policy
- `PutUserPolicy` - Inline user policy changes
- `PutRolePolicy` - Inline role policy changes
- `PutGroupPolicy` - Inline group policy changes
- `UpdateAssumeRolePolicy` - Role trust policy changes

## Required IAM Permissions

### Orchestrator Lambda Function

The orchestrator Lambda function requires the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMPolicyRetrieval",
      "Effect": "Allow",
      "Action": [
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:GetGroupPolicy",
        "iam:GetRole"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMPolicyAttachments",
      "Effect": "Allow",
      "Action": [
        "iam:ListEntitiesForPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "InvokeValidatorLambda",
      "Effect": "Allow",
      "Action": [
        "lambda:InvokeFunction"
      ],
      "Resource": "arn:aws:lambda:REGION:ACCOUNT_ID:function:VALIDATOR_FUNCTION_NAME"
    },
    {
      "Sid": "DynamoDBTracking",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:REGION:ACCOUNT_ID:table/iam-policy-validations"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:REGION:ACCOUNT_ID:log-group:/aws/lambda/*"
    }
  ]
}
```

### EventBridge Rule Pattern

```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "CreatePolicy",
      "CreatePolicyVersion",
      "PutUserPolicy",
      "PutRolePolicy",
      "PutGroupPolicy",
      "UpdateAssumeRolePolicy"
    ]
  }
}
```

## Configuration

Configuration is stored in `src/lambda/config.yaml`:

```yaml
validatorLambdaArn: "arn:aws:lambda:REGION:ACCOUNT_ID:function:VALIDATOR_FUNCTION_NAME"
dynamoDbTableName: "iam-policy-validations"
validationTtlDays: 90
```

## Deployment Requirements

1. **Python Runtime**: Python 3.9 or later
2. **Python Dependencies**: 
   - `boto3` (AWS SDK)
   - `PyYAML` (for config parsing)

3. **AWS Resources**:
   - CloudTrail with management events enabled
   - EventBridge rule configured with the pattern above
   - DynamoDB table with TTL enabled
   - Lambda execution role with required permissions

## DynamoDB Table Schema

**Table Name**: `iam-policy-validations`

**Attributes**:
- `validationId` (String, Partition Key) - Unique identifier for validation attempt
- `timestamp` (String) - ISO 8601 timestamp of validation
- `policyInfo` (Map) - Policy metadata (type, name, ARN, etc.)
- `eventMetadata` (Map) - CloudTrail event details
- `status` (String) - Validation status (PENDING, SUCCESS, FAILED)
- `ttl` (Number) - Time-to-live for automatic cleanup

**TTL Configuration**: Enable TTL on the `ttl` attribute

## Data Flow

1. IAM policy change occurs
2. CloudTrail logs the API call
3. EventBridge matches the event and triggers orchestrator Lambda
4. Orchestrator:
   - Extracts policy information from event
   - Retrieves full policy document from IAM
   - Lists all entities (users/roles/groups) attached to the policy
   - Records validation attempt in DynamoDB
   - Invokes validator Lambda asynchronously
5. Validator (to be implemented):
   - Validates policy syntax and semantics
   - Checks against compliance rules
   - Updates DynamoDB with results
   - Sends SNS notification if issues found

## Lambda Response Format

The orchestrator returns structured information including:

```json
{
  "policyInfo": {
    "eventType": "PutRolePolicy",
    "policyType": "inline-role",
    "roleName": "MyRole",
    "policyName": "MyPolicy"
  },
  "policyDocument": {
    "Version": "2012-10-17",
    "Statement": [...]
  },
  "attachments": {
    "users": ["user1", "user2"],
    "roles": ["role1"],
    "groups": ["group1"],
    "attachmentCount": 4
  },
  "eventMetadata": {
    "eventName": "PutRolePolicy",
    "eventTime": "2026-02-15T10:30:00Z",
    "principal": "arn:aws:iam::123456789012:user/admin",
    "sourceIpAddress": "203.0.113.0",
    "userAgent": "aws-cli/2.0.0"
  }
}
```

## Security Considerations

- The orchestrator Lambda requires read-only access to IAM policies
- All policy changes are logged and tracked in DynamoDB
- Consider implementing least privilege validation rules
- Review CloudTrail logs regularly for audit purposes
- Ensure DynamoDB table has encryption at rest enabled

## Future Enhancements

- Implement validator Lambda with configurable compliance rules
- Add SNS notifications for high-severity findings
- Create dashboard for visualization of policy changes
- Implement automated remediation for common issues
- Add support for resource-based policies (S3, Lambda, etc.)
