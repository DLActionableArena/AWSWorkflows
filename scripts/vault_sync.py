import boto3
import hvac
import os

DEFAULT_VAULT_ADDR = 'http://localhost:8200'
DEFAULT_VAULT_KV_PATH = 'kv'
DEFAULT_VAULT_SECRET_PATH = 'aws_secrets'
DEFAULT_AWS_REGION = 'us-east-2'

VAULT_ADDR = os.getenv("VAULT_ADDR", DEFAULT_VAULT_ADDR)
VAULT_KV_PATH = os.getenv("VAULT_KV_PATH", DEFAULT_VAULT_KV_PATH)
VAULT_SECRET_PATH = os.getenv("VAULT_SECRET_PATH ", DEFAULT_VAULT_SECRET_PATH)
VAULT_ROLE_ID = os.getenv("VAULT_ROLE_ID")
VAULT_SECRET_ID = os.getenv("VAULT_SECRET_ID")
AWS_REGION = os.getenv("AWS_REGION", DEFAULT_AWS_REGION)
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY_ID = os.getenv("AWS_SECRET_ACCESS_KEY_ID")

aws_client = None
vault_client = None

def initialize_clients():
    """Initialize HashiCorp Vault and AWS Clients"""
    global aws_client, vault_client

    # Initialize Vault client
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

    try:
        # Initialize AWS client
        aws_client = boto3.client(
            'secretsmanager',
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY_ID
        )

        # Suppress SSL warnings if needed
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        print("Testing clients connections")
        if vault_client.is_authenticated():
            print("Vault client authenticated successfully")
        else:
            raise Exception("Vault client authentication failed")

        return True
    except Exception as e:
        print(f"Error initializing AWS client: {e}")
        return False

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
    initialize_clients()
    print("Clients initialized successfully")

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