import boto3
import hvac
import os

DEFAULT_VAULT_ADDR = 'http://localhost:8200'
DEFAULT_VAULT_KV_PATH = 'kv'
DEFAULT_VAULT_SECRET_PATH = 'aws_secrets'
DEFAULT_AWS_REGION = 'us-east-2'
AWS_SECRETS_MANAGER = "secretsmanager"
AWS_SECURITY_TOKEN_SERVICE = "sts"

VERIFY_CERTIFICATE = os.getenv("VERIFY_CERTIFICATE", "False") == "True"
VAULT_ADDR = os.getenv("VAULT_ADDR", DEFAULT_VAULT_ADDR)
VAULT_KV_PATH = os.getenv("VAULT_KV_PATH", DEFAULT_VAULT_KV_PATH)
VAULT_SECRET_PATH = os.getenv("VAULT_SECRET_PATH ", DEFAULT_VAULT_SECRET_PATH)
VAULT_ROLE_ID = os.getenv("VAULT_ROLE_ID")
VAULT_SECRET_ID = os.getenv("VAULT_SECRET_ID")
AWS_REGION = os.getenv("AWS_REGION", DEFAULT_AWS_REGION)
#AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
#AWS_SECRET_ACCESS_KEY_ID = os.getenv("AWS_SECRET_ACCESS_KEY_ID")
AWS_ASSUMED_ROLE_NAME = os.getenv("AWS_ASSUMED_ROLE_NAME")
#AWS_ASSUMED_ROLE_ARN = os.getenv("AWS_ASSUMED_ROLE_ARN")
AWS_DYNAMIC_SECRETS_ENGINE_MOUNT_POINT = os.getenv("AWS_DYNAMIC_SECRETS_ENGINE_MOUNT_POINT", "aws_dynamic_secrets")

aws_client = None
vault_client = None

# https://python-hvac.org/en/stable/usage/secrets_engines/aws.html
def get_aws_dynamic_credentials_from_vault():
    """Retrieve AWS credentials from vault AWS secrets engines"""
    global vault_client

    list_roles_response = vault_client.secrets.aws.list_roles(
        mount_point="aws_dynamic_secrets"
    )
    print(f"AWS Roles are: {list_roles_response}")

    # Rotate the root credentials
    # client.secrets.aws.rotate_root_iam_credentials()

    # Retrieve credentials for the current operations
    # Will block to generate credentials, which sould be 10-15 sec in general
    aws_dynamic_creds = vault_client.secrets.aws.generate_credentials(
        name=AWS_ASSUMED_ROLE_NAME,
        mount_point=AWS_DYNAMIC_SECRETS_ENGINE_MOUNT_POINT
 #       ,role_arn=AWS_ASSUMED_ROLE_ARN
 #       
 #       ,endpoint="sts"
    )
    print(f"aws_dynamic_creds: {aws_dynamic_creds}")

    # Connect to AWS using temporary credentials
    if aws_dynamic_creds and \
       aws_dynamic_creds["data"] and \
       aws_dynamic_creds["data"]["access_key"] and \
       aws_dynamic_creds["data"]["secret_key"] and \
       aws_dynamic_creds["data"]["security_token"]:    
       initialize_aws(
          AWS_REGION,
          aws_dynamic_creds["data"]["access_key"],
          aws_dynamic_creds["data"]["secret_key"],
          aws_dynamic_creds["data"]["security_token"]
    )
       # print(f"Using the following credentials: region_name:{region_name} access_key: {access_key} secret_key: {secret_key} ")
    else:
       print(f"Missing one or more arg, data: {aws_dynamic_creds}")

    # aws_dynamic_creds: {
	# 'request_id': '22886e7f-fbd2-98e3-4cf0-34eba76dbbc6', 
	# 'lease_id': 'aws_dynamic_secrets/creds/AWS_SECRETS_SYNC_ROLE/Z0yFYkSj0yubANm0OA5Lzbyx', 
	# 'renewable': False, 
	# 'lease_duration': 3599, 
	# 'data': {
	# 	'access_key': 'ASIAVUEFWSH5CY3FSLXF', 
	# 	'arn': 'arn:aws:sts::386827457018:assumed-role/AWS_SECRETS_SYNC_ROLE/vault-approle-AWS_SECRETS_SYNC_ROLE-1761588617-LW3mlHTt49SKDNCDj', 
	# 	'secret_key': 'eDqJgu1n30LBGpHn6ANDAMwERuSu+V/arCW0B0Pc', 
	# 	'security_token': 'IQoJb3JpZ2luX2VjEPL//////////wEaCXVzLWVhc3QtMiJHMEUCIQDBAFc....', 
	# 	'session_token': 'IQoJb3JpZ2luX2VjEPL//////////wEaCXVzLWVhc3QtMiJHMEUCIQDBAFcB....', 
	# 	'ttl': 3599
	# 	}, 
	# 'wrap_info': None, 
	# 'warnings': None, 
	# 'auth': None, 
	# 'mount_type': 'aws'

    # Role Trust Relationaship
    # Trust relationship:
    # {
    #     "Version": "2012-10-17",
    #     "Statement": [
    #         {
    #             "Effect": "Allow",
    #             "Principal": {
    #                 "Federated": "arn:aws:iam::386827457018:oidc-provider/token.actions.githubusercontent.com"
    #             },
    #             "Action": "sts:AssumeRoleWithWebIdentity",
    #             "Condition": {
    #                 "StringEquals": {
    #                     "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    #                 },
    #                 "StringLike": {
    #                     "token.actions.githubusercontent.com:sub": "repo:DLActionableArena/AWSWorkflows:environment:*"
    #                 }
    #             }
    #         },
    #         {
    #             "Effect": "Allow",
    #             "Principal": {
    #                 "AWS": "arn:aws:iam::386827457018:user/VaultAWSSecretsEngineServiceAccount"
    #             },
    #             "Action": "sts:AssumeRole"
    #         }
    #     ]
    # }




def list_vault_secrets():
    """List existing vault secrets"""
    global vault_client
    secrets = vault_client.secrets.kv.v2.list_secrets(
        mount_point="kv",
        path="applications"
    )
    print(f"Test secrets: {secrets}")


def initialize_aws(
        region_name_arg,
        access_key_arg,
        secret_key_arg,
        security_token_arg
    ):
    """Intialize the AWS Client"""
    global aws_client

    # NOTE: The following permissions originally added to the service account/root does not seem to be required i=on this side
    #       just in the tole trust relationship only
    #   {
	#		"Effect": "Allow",
	#		"Action": "sts:AssumeRole",
	#		"Resource": "arn:aws:iam::386827457018:role/AWS_SECRETS_SYNC_ROLE"
	#	}

    try:
        # Initialize AWS client
        session = boto3.Session(
            region_name = region_name_arg, # AWS_REGION,
            aws_access_key_id = access_key_arg, # AWS_ACCESS_KEY_ID,
            aws_secret_access_key = secret_key_arg, #AWS_SECRET_ACCESS_KEY_ID
            aws_session_token = security_token_arg
        )

        # Suppress SSL warnings if needed
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        sts_client = session.client(
            AWS_SECURITY_TOKEN_SERVICE,
            verify=VERIFY_CERTIFICATE
        )
        sts_client.get_caller_identity()

        aws_client = session.client(
            AWS_SECRETS_MANAGER,
            verify=VERIFY_CERTIFICATE
        )

        return True
    except Exception as e:
        print(f"Error initializing AWS client: {e}")
        return False

def initialize_vault():
    """Initialize the HashiCorp Vault client"""
    global vault_client

    vault_client = hvac.Client(url=VAULT_ADDR)
    if VAULT_ROLE_ID and VAULT_SECRET_ID:
        auth_response = vault_client.auth.approle.login(
            role_id=VAULT_ROLE_ID,
            secret_id=VAULT_SECRET_ID
        )
        if not auth_response['auth']['client_token']:
            raise Exception("Vault authentication failed")
    else:
        raise Exception("Vault ROLE_ID and SECRET_ID must be set")
    
    # Suppress SSL warnings if needed
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print("Testing clients connections")
    if vault_client.is_authenticated():
        print("Vault client authenticated successfully")
    else:
        raise Exception("Vault client authentication failed")

def get_all_aws_secrets():
    """Retrieve all AWS secrets"""
    secrets = []
    paginator = aws_client.get_paginator('list_secrets')
    for page in paginator.paginate():
        secrets.extend(page.get('SecretList', []))
    return secrets

def get_secret_value(secret_name):
    """Retrieve a specific secret value from AWS Secrets Manager"""
    try:
        response = aws_client.get_secret_value(SecretId=secret_name)
        return response.get('SecretString', None)
    except Exception as e:
        print(f"Error retrieving secret {secret_name}: {e}")
        return None


def get_secret_details(secret_name):
    """Retrieve details of a specific secret from AWS Secrets Manager"""
    try:
        response = aws_client.describe_secret(SecretId=secret_name)
        print(f"Describe secret {secret_name}: {response}")
        return response
    except Exception as e:
        print(f"Error retrieving secret details for {secret_name}: {e}")
        return None

def get_secret_rotation_info(secret_name):
    """
    Retrieves rotation information for a given secret in AWS Secrets Manager.
    Args:
        secret_name (str): The name or ARN of the secret.
    Returns:
        dict: A dictionary containing the secret's rotation configuration,
              or None if no rotation is configured or an error occurs.
    """
    try:
        response = aws_client.describe_secret(SecretId=secret_name)

        if "RotationEnabled" in response and response["RotationEnabled"]:
            rotation_rules = response.get("RotationRules")
            return rotation_rules

    except aws_client.exceptions.ResourceNotFoundException:
        print(f"Secret '{secret_name}' not found.")
        return None


def main():
    """"Main function to demonstrate functionality"""
    initialize_vault()
    print("Vault Client initialized successfully")

    print("About to test AWS credentials...")
    list_vault_secrets()
    get_aws_dynamic_credentials_from_vault()


    # Extract and process AWS secrets
    secrets = get_all_aws_secrets()
    print(f"Retrieved {len(secrets)} secrets from AWS Secrets Manager: ", secrets)

    for i, secret in enumerate(secrets, 1):
        secret_name = secret['Name']
        print(f"\n[{i}] Secret Name: {secret_name}")

        try:
            secret_value = get_secret_value(secret_name)
            print(f"Secret Value: {secret_value}")

            get_secret_details(secret_name)

            rotation_details = get_secret_rotation_info(secret_name)
            if rotation_details:
                print(f"Rotation Details: {rotation_details}")
            else:
                print("No rotation details available")
        except Exception as e:
            print(f"Error retrieving details for secret {secret_name}: {e}")
            continue

    
if __name__ == "__main__":
    main()