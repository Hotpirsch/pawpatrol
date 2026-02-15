import json
import boto3
import os
import yaml
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Initialize AWS clients
iam_client = boto3.client('iam')
lambda_client = boto3.client('lambda')
dynamodb = boto3.resource('dynamodb')

# Load configuration
def load_config() -> Dict[str, Any]:
    """
    Load configuration from config file.
    """
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Config file not found at {config_path}, using defaults")
        return {
            'validatorLambdaArn': os.environ.get('VALIDATOR_LAMBDA_ARN', ''),
            'dynamoDbTableName': os.environ.get('DYNAMODB_TABLE_NAME', 'iam-policy-validations'),
            'validationTtlDays': 90
        }
    except yaml.YAMLError as e:
        print(f"Error parsing config file: {e}")
        raise

config = load_config()
VALIDATOR_LAMBDA_ARN = config.get('validatorLambdaArn')
DYNAMODB_TABLE_NAME = config.get('dynamoDbTableName', 'iam-policy-validations')
VALIDATION_TTL_DAYS = config.get('validationTtlDays', 90)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Orchestrator Lambda that processes IAM policy change events from EventBridge.
    Retrieves the policy and invokes the validator Lambda.
    """
    print(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract event details
        detail = event.get('detail', {})
        event_name = detail.get('eventName')
        request_parameters = detail.get('requestParameters', {})
        response_elements = detail.get('responseElements', {})
        event_time = detail.get('eventTime')
        user_identity = detail.get('userIdentity', {})
        
        # Extract policy information based on event type
        policy_info = extract_policy_info(event_name, request_parameters, response_elements)
        
        if not policy_info:
            print(f"Could not extract policy info from event: {event_name}")
            return {'statusCode': 400, 'body': 'Invalid event'}
        
        # Retrieve the actual policy document
        policy_document = retrieve_policy_document(policy_info)
        
        if not policy_document:
            print(f"Could not retrieve policy document for: {policy_info}")
            return {'statusCode': 404, 'body': 'Policy not found'}
        
        # Get policy attachment information
        attachments = get_policy_attachments(policy_info)
        
        # Prepare validation request
        validation_request = {
            'policyInfo': policy_info,
            'policyDocument': policy_document,
            'attachments': attachments,
            'eventMetadata': {
                'eventName': event_name,
                'eventTime': event_time,
                'principal': user_identity.get('principalId'),
                'sourceIpAddress': detail.get('sourceIPAddress'),
                'userAgent': detail.get('userAgent')
            }
        }
        
        # Record validation attempt in DynamoDB
        validation_id = record_validation_attempt(validation_request)
        validation_request['validationId'] = validation_id
        
        # Invoke validator Lambda
        print(f"Invoking validator Lambda for: {policy_info}")
        response = lambda_client.invoke(
            FunctionName=VALIDATOR_LAMBDA_ARN,
            InvocationType='Event',  # Asynchronous invocation
            Payload=json.dumps(validation_request)
        )
        
        print(f"Validator invoked successfully. Status: {response['StatusCode']}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Policy validation initiated',
                'validationId': validation_id,
                'policyInfo': policy_info
            })
        }
        
    except Exception as e:
        print(f"Error processing event: {str(e)}")
        import traceback
        traceback.print_exc()
        return {'statusCode': 500, 'body': f'Error: {str(e)}'}


def extract_policy_info(event_name: str, request_params: Dict, response_elements: Dict) -> Optional[Dict[str, str]]:
    """
    Extract policy information based on the IAM event type.
    """
    policy_info = {'eventType': event_name}
    
    if event_name == 'CreatePolicy':
        policy_info.update({
            'policyType': 'managed',
            'policyArn': response_elements.get('policy', {}).get('arn'),
            'policyName': request_params.get('policyName')
        })
        
    elif event_name == 'CreatePolicyVersion':
        policy_info.update({
            'policyType': 'managed',
            'policyArn': request_params.get('policyArn'),
            'versionId': response_elements.get('policyVersion', {}).get('versionId'),
            'isDefault': request_params.get('setAsDefault', False)
        })
        
    elif event_name == 'PutUserPolicy':
        policy_info.update({
            'policyType': 'inline-user',
            'userName': request_params.get('userName'),
            'policyName': request_params.get('policyName')
        })
        
    elif event_name == 'PutRolePolicy':
        policy_info.update({
            'policyType': 'inline-role',
            'roleName': request_params.get('roleName'),
            'policyName': request_params.get('policyName')
        })
        
    elif event_name == 'PutGroupPolicy':
        policy_info.update({
            'policyType': 'inline-group',
            'groupName': request_params.get('groupName'),
            'policyName': request_params.get('policyName')
        })
        
    elif event_name == 'UpdateAssumeRolePolicy':
        policy_info.update({
            'policyType': 'trust-policy',
            'roleName': request_params.get('roleName'),
            'policyName': 'AssumeRolePolicyDocument'
        })
        
    else:
        return None
    
    return policy_info


def retrieve_policy_document(policy_info: Dict[str, str]) -> Optional[Dict]:
    """
    Retrieve the actual policy document from IAM based on policy type.
    """
    try:
        policy_type = policy_info.get('policyType')
        
        if policy_type == 'managed':
            # Get managed policy
            policy_arn = policy_info.get('policyArn')
            version_id = policy_info.get('versionId')
            
            if not version_id:
                # Get default version
                policy = iam_client.get_policy(PolicyArn=policy_arn)
                version_id = policy['Policy']['DefaultVersionId']
            
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )
            return policy_version['PolicyVersion']['Document']
            
        elif policy_type == 'inline-user':
            # Get inline user policy
            response = iam_client.get_user_policy(
                UserName=policy_info.get('userName'),
                PolicyName=policy_info.get('policyName')
            )
            return response['PolicyDocument']
            
        elif policy_type == 'inline-role':
            # Get inline role policy
            response = iam_client.get_role_policy(
                RoleName=policy_info.get('roleName'),
                PolicyName=policy_info.get('policyName')
            )
            return response['PolicyDocument']
            
        elif policy_type == 'inline-group':
            # Get inline group policy
            response = iam_client.get_group_policy(
                GroupName=policy_info.get('groupName'),
                PolicyName=policy_info.get('policyName')
            )
            return response['PolicyDocument']
            
        elif policy_type == 'trust-policy':
            # Get role trust policy (assume role policy document)
            response = iam_client.get_role(
                RoleName=policy_info.get('roleName')
            )
            return response['Role']['AssumeRolePolicyDocument']
            
    except Exception as e:
        print(f"Error retrieving policy document: {str(e)}")
        return None


def get_policy_attachments(policy_info: Dict[str, str]) -> Dict[str, Any]:
    """
    Get information about where the policy is attached (users, roles, groups).
    """
    attachments = {
        'users': [],
        'roles': [],
        'groups': [],
        'attachmentCount': 0
    }
    
    try:
        policy_type = policy_info.get('policyType')
        
        if policy_type == 'managed':
            # For managed policies, list all entities attached
            policy_arn = policy_info.get('policyArn')
            
            # Get attached users
            try:
                paginator = iam_client.get_paginator('list_entities_for_policy')
                for page in paginator.paginate(PolicyArn=policy_arn, EntityFilter='User'):
                    for user in page.get('PolicyUsers', []):
                        attachments['users'].append(user['UserName'])
            except Exception as e:
                print(f"Error listing users for policy: {str(e)}")
            
            # Get attached roles
            try:
                paginator = iam_client.get_paginator('list_entities_for_policy')
                for page in paginator.paginate(PolicyArn=policy_arn, EntityFilter='Role'):
                    for role in page.get('PolicyRoles', []):
                        attachments['roles'].append(role['RoleName'])
            except Exception as e:
                print(f"Error listing roles for policy: {str(e)}")
            
            # Get attached groups
            try:
                paginator = iam_client.get_paginator('list_entities_for_policy')
                for page in paginator.paginate(PolicyArn=policy_arn, EntityFilter='Group'):
                    for group in page.get('PolicyGroups', []):
                        attachments['groups'].append(group['GroupName'])
            except Exception as e:
                print(f"Error listing groups for policy: {str(e)}")
                
        elif policy_type == 'inline-user':
            # Inline user policy is inherently attached to the user
            attachments['users'].append(policy_info.get('userName'))
            
        elif policy_type == 'inline-role':
            # Inline role policy is inherently attached to the role
            attachments['roles'].append(policy_info.get('roleName'))
            
        elif policy_type == 'inline-group':
            # Inline group policy is inherently attached to the group
            attachments['groups'].append(policy_info.get('groupName'))
            
        elif policy_type == 'trust-policy':
            # Trust policy is inherently attached to the role
            attachments['roles'].append(policy_info.get('roleName'))
        
        # Calculate total attachments
        attachments['attachmentCount'] = (
            len(attachments['users']) + 
            len(attachments['roles']) + 
            len(attachments['groups'])
        )
        
        print(f"Policy attachments found: {attachments['attachmentCount']} total")
        
    except Exception as e:
        print(f"Error getting policy attachments: {str(e)}")
    
    return attachments


def record_validation_attempt(validation_request: Dict) -> str:
    """
    Record the validation attempt in DynamoDB for tracking.
    """
    try:
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        
        validation_id = f"{validation_request['eventMetadata']['eventTime']}-{hash(json.dumps(validation_request['policyInfo']))}"
        
        item = {
            'validationId': validation_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'policyInfo': validation_request['policyInfo'],
            'eventMetadata': validation_request['eventMetadata'],
            'status': 'PENDING',
            'ttl': int(datetime.now(timezone.utc).timestamp()) + (VALIDATION_TTL_DAYS * 24 * 60 * 60)
        }
        
        table.put_item(Item=item)
        print(f"Recorded validation attempt: {validation_id}")
        
        return validation_id
        
    except Exception as e:
        print(f"Error recording validation attempt: {str(e)}")
        # Return a generated ID even if DynamoDB fails
        return f"error-{datetime.now(timezone.utc).timestamp()}"
