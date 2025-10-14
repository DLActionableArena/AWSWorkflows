import os
import boto3
import urllib3
import json

DEFAULT_AWS_REGION = "us-east-2"
DEFAULT_VAULT_PATH = "aws/services"
AWS_SECRET_MANAGER="secretsmanager"
AWS_SECURITY_TOKEN_SERVICE="sts"
VAULT_AWS_SECRET_PATH = DEFAULT_VAULT_PATH if DEFAULT_VAULT_PATH.endswith("/") \
                                           else  f"{DEFAULT_VAULT_PATH}/"
VAULT_AWS_SECRET_PATH_LEN = len(VAULT_AWS_SECRET_PATH)

#AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
#AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN")
AWS_REGION = os.getenv("AWS_REGION", DEFAULT_AWS_REGION)
AWS_ROLE_TO_ASSUME = os.getenv("AWS_ROLE_TO_ASSUME")
AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION")


aws_client = None

# Secrets Dictionary: {
#     "nprod/SyncAction": {
#         "BogusToken": "989e9ab0-de1e-4a12-9bad-a7b531cda777"
#     },
#     "nprod/AnotherAppSecret": {
#         "Another secret": "86bbb505-4499-4de0-9bff-60635b5b250c"
#     },
#     "nprod/Service/MutliRowSecret": {
#         "key1": "value1",
#         "key2": "value2",
#         "key3": "value3"
#     }
# }

def replicate_secret_change_to_regions(secret_name, secret_value):
    """Replicate a secret change to all regions"""
    # SecretsManager.Client.replicate_secret_to_regions(**kwargs) ???
    #   Required permissions:
    #       secretsmanager:ReplicateSecretToRegions
    #       if  encrypted with custom key: kms:Decrypt, kms:GenerateDataKey and kms:Encrypt
    try:
        # TODO - Check this code
        response = aws_client.replicate_secret_to_regions(
            SecretId=secret_name,
            AddReplicaRegions=[
                {
                    'Region': 'string',
                    # 'KmsKeyId': 'string'
                },
            ]
        )
        print(f"Replicated secret {secret_name} to regions: {response}")
        return response
    except Exception as e:
        print(f"Error replicating secret {secret_name}: {e}")
        return None

def update_aws_secret(aws_secret_name, aws_secret_value):
    """Update an AWS secret"""
    print(f"Would update AWS secret with name: {aws_secret_name} with value {aws_secret_value}")

    # SecretsManager.Client.update_secret(**kwargs)
    #   Use when you need to modify the secret"s metadata (description, KMS key, rotation configuration)
    #       and/or update the secret value.
    #   Required permissions:
    #       secretsmanager:UpdateSecret
    #       if  encrypted with custom key: kms:Decrypt, kms:GenerateDataKey and kms:Encrypt

    # SecretsManager.Client.put_secret_value(**kwargs)
    #   CANNOT USE if have one or more replication regions
    #   Use when your sole purpose is to provide a new secret value, creating a new version of the secret,
    #       and you don"t need to modify any other attributes.
    #   Purpose: This method is used to add a new version of a secret to an existing secret.
    #            It updates the secret"s value while retaining the history of previous versions.
    #   When to use: Use put_secret_value when you need to update the value of an already existing secret,
    #                such as during a secret rotation or when a credential changes.
    #   Required permissions: secretsmanager:PutSecretValue

def create_aws_secret(secret_name, secret_value):
    """Create an AWS secret"""
    print(f"Would create AWS secret with name: {secret_name} with value {secret_value}")

    # SecretsManager.Client.create_secret(**kwargs)  # ForceOverwriteReplicaSecret ???
    #   USE if have one or more replication regions
    #   Required permissions:
    #       secretsmanager:CreateSecret
    #       IF INCLUDE TAG: secretsmanager:TagResource
    #       To AddReplicaRegions, you must also have secretsmanager:ReplicateSecretToRegions
    #   Purpose: This method is used to create a brand new secret in AWS Secrets Manager.
    #            It establishes the secret"s name, description, and initial secret value.
    #   When to use: Use create_secret when you are storing a secret for the first time,
    #                and no secret with the specified name currently exists in Secrets Manager.


    # try:
    #     aws_secret_name = VAULT_AWS_SECRET_PATH
    #     response = aws_client.create_secret(
    #         Name=secret_name,
    #         SecretString=secret_value
    #     )
    #     print(f"Secret {secret_name} created successfully.")
    #     return response
    # except aws_client.exceptions.ResourceExistsException:
    #     print(f"Secret {secret_name} already exists.")
    # except Exception as e:
    #     print(f"Error creating secret: {e}")

def process_secret_regions(secret_name):
    """Process the specified secret regions"""
    replicated_regions = get_replicated_regions(secret_name)
    if replicated_regions:
        print(f"Secret {secret_name} is replicated to regions: {replicated_regions}")
        # TODO - Replicate to all configured regions
    else:
        print(f"Secret {secret_name} is not replicated to any regions")

def get_replicated_regions(secret_id):
    """
    Retrieves the regions a secret is replicated to.

    Args:
        secret_id (str): The ARN or friendly name of the secret.

    Returns:
        list: A list of region names where the secret is replicated,
              or an empty list if not replicated or an error occurs.
    """
    # TODO - Check this code
    client = boto3.client("secretsmanager")
    try:
        response = client.describe_secret(SecretId=secret_id)
        replicated_regions = []
        if "ReplicationStatus" in response:
            for replica in response["ReplicationStatus"]:
                if "Region" in replica:
                    replicated_regions.append(replica["Region"])
        return replicated_regions
    except client.exceptions.ResourceNotFoundException:
        print(f"Secret {secret_id} not found.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def extract_secret_name(vault_secret_name):
    """Returns the secret name from the provided path"""
    print(f"Extracting secret name: {vault_secret_name} Len vault secret: {len(vault_secret_name)} against {VAULT_AWS_SECRET_PATH_LEN} ")
    print(f"Is substring: {vault_secret_name.startswith(VAULT_AWS_SECRET_PATH)}")
    secret_name = vault_secret_name
    if  len(vault_secret_name) > VAULT_AWS_SECRET_PATH_LEN and \
        vault_secret_name.startswith(VAULT_AWS_SECRET_PATH):
        secret_name = vault_secret_name[VAULT_AWS_SECRET_PATH_LEN:]

    return secret_name

def process_secrets(aws_secrets, vault_secret_name, vault_secret_value):
    """Process the specified secrets path and data"""
    # Convert the secret value to JSON string for change validation
    vault_secret_value_str = json.dumps(vault_secret_value, sort_keys=True) # Convert to string/JSON
    vault_secret_name_match =  extract_secret_name(vault_secret_name)

    # TODO - Remove this
    print(f"VAULT_AWS_SECRET_PATH is {VAULT_AWS_SECRET_PATH} with VAULT_AWS_SECRET_PATH_LEN {VAULT_AWS_SECRET_PATH_LEN}")
    print(f"JSON string version of vault value: {vault_secret_value_str}")
    print(f"The Vault secret name to match: {vault_secret_name_match}")


    # Iterate through AWS Secrets to locate any match and update if found
    for aws_secret in aws_secrets.items():
        aws_secret_name  = aws_secret[0]
        aws_secret_value = aws_secret[1]

        # Validate that the AWS secret name matches the vault secret name
        if aws_secret_name == vault_secret_name_match:
            # TODO - Remove this
            print(f"AWS secret_name {aws_secret_name} is identical to Vault secret name: {vault_secret_name_match} ")
            aws_secret_value_str = json.dumps(aws_secret_value, sort_keys=True)
            if vault_secret_value_str != aws_secret_value_str:
                print(f"Value change detected for AWS secret with name {aws_secret_name}, updating")
                update_aws_secret(aws_secret_name, vault_secret_value)
                process_secret_regions(aws_secret_name)
            else:
                print(f"Secret with name {aws_secret_name} did not change, AWS version remains unchanged")
            return
        else:
            # TODO - Remove this, just for testing
            print(f"AWS Secret with name: {aws_secret_name} does not match vault secret with name: {vault_secret_name_match}")

    # Create a new AWS secret
    create_aws_secret(aws_secret_name, vault_secret_value)
    process_secret_regions(aws_secret_name)

def get_secret_value(secret_name):
    """Retrieve a specific secret value from AWS Secrets Manager"""
    try:
        response = aws_client.get_secret_value(SecretId=secret_name)
        return response.get("SecretString", None)
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
        dict: A dictionary containing the secret"s rotation configuration,
              or None if no rotation is configured or an error occurs.
    """
    try:
        response = aws_client.describe_secret(SecretId=secret_name)

        if "RotationEnabled" in response and response["RotationEnabled"]:
            rotation_rules = response.get("RotationRules")
            return rotation_rules

    except aws_client.exceptions.ResourceNotFoundException:
        print(f"Secret {secret_name} not found.")
        return None

def get_all_aws_secrets():
    """Retrieve all AWS secrets"""
    secrets = {}
    secrets_details = []
    paginator = aws_client.get_paginator("list_secrets")
    for page in paginator.paginate():
        secrets_details.extend(page.get("SecretList", []))
    print(f"Total secrets found: {len(secrets_details)} with keys: {secrets_details}")

    for secret in secrets_details:
        try:
            secret_name = secret["Name"]
            secrets[secret_name] = json.loads(get_secret_value(secret_name))
        except Exception as e:
            print(f"Error retrieving details for secret {secret_name}: {e}")
            continue
    return secrets

# Simulate process_secrets in original code
def process_mock_vault_data(aws_secrets):
    """Mock Vault data for testing"""
    # Secret name must contain only alphanumeric characters and the characters /_+=.@-
    mock_vault_data = {
        "aws/services/app/Secrets" : {"BogusKey":"BogusSecret", "dumb-secret":"123"},
        "aws/services/app1/Secrets" : {"secret1":"value1"},
        "aws/services/app2/Secrets" : {"secret2":"value2"},
        "aws/services/nprod/SyncAction" : {"BogusToken": "989e9ab0-de1e-4a12-9bad-a7b531cda777"},
        "aws/services/nprod/AnotherAppSecret" : {"Secret": "47aaa505-4499-4de0-9baa-60635b5b250c", "Another secret": "86bbb505-4499-4de0-9bff-60635b5b250c"},
        "aws/services/nprod/Service/MutliRowSecret" : {"key2": "value2", "key1": "value1", "key3": "value3"}
    }

    # Iterate through all the secrets and process them one at a time
    for secret in mock_vault_data.items():
        secret_name = secret[0]
        secret_value = secret[1]
        process_secrets(aws_secrets, secret_name, secret_value)

def initialize_clients():
    """Initialize HashiCorp Vault and AWS Clients"""
    global aws_client

    try:
        # Initialize AWS client using emvironment variable
        aws_client = boto3.client("secretsmanager")

        # Use sts to validate we are really authenticated else witl throw
        sts_client = boto3.client("sts")
        sts_client.get_caller_identity()

        # Suppress SSL warnings if needed
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        return True
    except Exception as e:
        print(f"Error initializing AWS client: {e}")
        return False

def main():
    """"Main function to demonstrate functionality"""
    initialize_clients()
    print("Clients initialized successfully")

    aws_secrets = get_all_aws_secrets()
    process_mock_vault_data(aws_secrets)

#    print(f"Retrieved {len(aws_secrets)} secrets from AWS Secrets Manager with secrets: {aws_secrets}")
#    print(f"First secret: {aws_secrets["nprod/SyncAction"]}")
#    print(f"Second secret: {aws_secrets["nprod/AnotherAppSecret"]}")
#    print(f"Third secret: {aws_secrets["nprod/Service/MutliRowSecret"]}")

# Secret name must contain only alphanumeric characters and the characters /_+=.@-
# nprod/Service/MutliRowSecret - Secret Value: {}
# nprod/AnotherAppSecret - Secret Value: {"Another secret" : "86bbb505-4499-4de0-9bff-60635b5b250c"}
# nprod/SyncAction - Secret Value: {"BogusToken":"989e9ab0-de1e-4a12-9bad-a7b531cda777"}


    # process_secret(aws_secrets, secret_name)
    # for i, secret in enumerate(secrets, 1):
    #     secret_name = secret["Name"]
    #     print(f"\n[{i}] Secret Name: {secret_name}")

    #     try:
    #         # secret_value = get_secret_value(secret_name)
    #         secret_value = json.loads(get_secret_value(secret_name))
    #         if secret_value is not None:
    #             # key, value = secret_value.popitem()
    #             for  key, value in secret_value.items():
    #                 print(f"Secret Value: key: {key} value: {value}")
    #                 get_secret_details(secret_name)

    #         rotation_details = get_secret_rotation_info(secret_name)
    #         if rotation_details:
    #             print(f"Rotation Details: {rotation_details}")
    #         else:
    #             print("No rotation details available")
    #     except Exception as e:
    #         print(f"Error retrieving details for secret {secret_name}: {e}")
    #         continue

if __name__ == "__main__":
    main()