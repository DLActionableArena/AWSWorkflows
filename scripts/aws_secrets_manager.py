import os
import boto3
import json

DEFAULT_AWS_REGION = 'us-east-2'
AWS_SECRET_MANAGER='secretsmanager'
AWS_SECURITY_TOKEN_SERVICE='sts'

AWS_REGION = os.getenv("AWS_REGION", DEFAULT_AWS_REGION)
#AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
#AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN")
AWS_ROLE_TO_ASSUME = os.getenv("AWS_ROLE_TO_ASSUME")
AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION")


# def create_multi_row_secret(secret_name, region_name, secret_data):
#     """
#     Creates a multi-row secret in AWS Secrets Manager.

#     Args:
#         secret_name (str): The name of the secret to create.
#         region_name (str): The AWS region where the secret will be stored.
#         secret_data (dict): A dictionary containing the key-value pairs for the secret.
#     """
#     client = boto3.client('secretsmanager', region_name=region_name)

#     try:
#         # Convert the dictionary to a JSON string
#         secret_string = json.dumps(secret_data)

#         response = client.create_secret(
#             Name=secret_name,
#             SecretString=secret_string
#         )
#         print(f"Secret '{secret_name}' created successfully.")
#         return response
#     except client.exceptions.ResourceExistsException:
#         print(f"Secret '{secret_name}' already exists.")
#     except Exception as e:
#         print(f"Error creating secret: {e}")

# # Example usage:
# if __name__ == "__main__":
#     my_secret_name = "MyMultiRowSecret"
#     my_region = "us-east-1"  # Replace with your desired region

#     # Define your secret data as a dictionary
#     my_secret_data = {
#         "username": "admin",
#         "password": "supersecretpassword",
#         "api_key": "your_api_key_here",
#         "database_url": "jdbc:mysql://localhost:3306/mydb"
#     }

#     create_multi_row_secret(my_secret_name, my_region, my_secret_data)




# def get_replicated_regions(secret_id):
#     """
#     Retrieves the regions a secret is replicated to.

# Args:
#         secret_id (str): The ARN or friendly name of the secret.

# Returns:
#         list: A list of region names where the secret is replicated,
#               or an empty list if not replicated or an error occurs.
#     """
#     client = boto3.client("secretsmanager")
#     try:
#         response = client.describe_secret(SecretId=secret_id)
#         replicated_regions = []
#         if "ReplicationStatus" in response:
#             for replica in response["ReplicationStatus"]:
#                 if "Region" in replica:
#                     replicated_regions.append(replica["Region"])
#         return replicated_regions
#     except client.exceptions.ResourceNotFoundException:
#         print(f"Secret '{secret_id}' not found.")
#         return []
#     except Exception as e:
#         print(f"An error occurred: {e}")
#         return []

# # Example usage:
# secret_name = "my-replicated-secret"  # Replace with your secret's name or ARN
# regions = get_replicated_regions(secret_name)

# if regions:
#     print(f"Secret '{secret_name}' is replicated to the following regions: {', '.join(regions)}")
# else:
#     print(f"Secret '{secret_name}' is not replicated to any regions or an error occurred.") 



aws_client = None

# Target Region ???
# SecretsManager.Client.create_secret(**kwargs)  # ForceOverwriteReplicaSecret ???
#   USE if have one or more replication regions
#   Required permissions:
#       secretsmanager:CreateSecret
#       IF INCLUDE TAG: secretsmanager:TagResource
#       To AddReplicaRegions, you must also have secretsmanager:ReplicateSecretToRegions
#   Purpose: This method is used to create a brand new secret in AWS Secrets Manager. 
#            It establishes the secret's name, description, and initial secret value.
#   When to use: Use create_secret when you are storing a secret for the first time, 
#                and no secret with the specified name currently exists in Secrets Manager.
# SecretsManager.Client.update_secret(**kwargs)
#   Use when you need to modify the secret's metadata (description, KMS key, rotation configuration) 
#       and/or update the secret value.
#   Required permissions:
#       secretsmanager:UpdateSecret
#       if  encrypted with custom key: kms:Decrypt, kms:GenerateDataKey and kms:Encrypt
# SecretsManager.Client.put_secret_value(**kwargs)
#   CANNOT USE if have one or more replication regions
#   Use when your sole purpose is to provide a new secret value, creating a new version of the secret, 
#       and you don't need to modify any other attributes.
#   Purpose: This method is used to add a new version of a secret to an existing secret. 
#            It updates the secret's value while retaining the history of previous versions.
#   When to use: Use put_secret_value when you need to update the value of an already existing secret, 
#                such as during a secret rotation or when a credential changes.
#
#   Required permissions: secretsmanager:PutSecretValue
# SecretsManager.Client.replicate_secret_to_regions(**kwargs) ???
#   Required permissions:
#       secretsmanager:ReplicateSecretToRegions
#       if  encrypted with custom key: kms:Decrypt, kms:GenerateDataKey and kms:Encrypt


# Secrets Dictionary: {
#     'nprod/SyncAction': {
#         'BogusToken': '989e9ab0-de1e-4a12-9bad-a7b531cda777'
#     },
#     'nprod/AnotherAppSecret': {
#         'Another secret': '86bbb505-4499-4de0-9bff-60635b5b250c'
#     },
#     'nprod/Service/MutliRowSecret': {
#         'key1': 'value1',
#         'key2': 'value2',
#         'key3': 'value3'
#     }
# }

def process_secret(aws_secrets, secret_name):
    """Process secrets"""
    
    

def get_all_aws_secrets():
    """Retrieve all AWS secrets"""
    secrets = {}
    secrets_details = []
    paginator = aws_client.get_paginator('list_secrets')
    for page in paginator.paginate():
        secrets_details.extend(page.get('SecretList', []))
    print(f"Total secrets found: {len(secrets_details)} with keys: {secrets_details}")

    for secret in secrets_details:
        try:
            secret_name = secret['Name']
            secrets[secret_name] = json.loads(get_secret_value(secret_name))
        except Exception as e:
            print(f"Error retrieving details for secret {secret_name}: {e}")
            continue
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



#  secrets = key_name.split('/')[-1]

def update_aws_secret(secret_name, secret_value):
    """Update an AWS secret"""

def create_aws_secret(secret_name, secret_value):
    """Create an AWS secret"""

# TODO - NOT EXACLT LIKE VAULT DUE TO MOCK
def process_secrets(aws_secrets, secrets_path, data):
    """Process the """ 


# Simulate process_secrets in original code
def process_mock_vault_data(aws_secrets):
    """Mock Vault data for testing"""
    # Secret name must contain only alphanumeric characters and the characters /_+=.@-
    mock_vault_data = {
        'aws/secrets' : {'BogusKey':'BogusSecret', 'dumb-secret':'123'},
        'aws/services/app1' : {'secret1':'value1'},
        'aws/services/app2' : {'secret2':'value2'},
        'aws/services/app3/nprod/SyncAction' : {'BogusToken': '989e9ab0-de1e-4a12-9bad-a7b531cda777'},
        'aws/services/app3/nprod/AnotherAppSecret' : {'Another secret': '86bbb505-4499-4de0-9bff-60635b5b250c', 'Next secret': '47aaa505-4499-4de0-9baa-60635b5b250c'},
        'nprod/Service/MutliRowSecret' : {'key1': 'value1', 'key2': 'value2', 'key3': 'value3a'}
    }

    for item in mock_vault_data.items():
        print(f"Mock Vault Data - Path: {item[0]} Data: {item[1]}")
#    for secret_path in mock_vault_data:
#        secret_data = mock_vault_data[secret_path]
#        process_secrets(aws_secrets, secret_path, secret_data)


def initialize_clients():
    """Initialize HashiCorp Vault and AWS Clients"""
    global aws_client

    try:
        # Initialize AWS client using emvironment variable
        aws_client = boto3.client('secretsmanager')

        # Use sts to validate we are really authenticated else witl throw
        sts_client = boto3.client('sts')
        sts_client.get_caller_identity()

        # Suppress SSL warnings if needed
        import urllib3
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
# nprod/AnotherAppSecret - Secret Value: {'Another secret' : '86bbb505-4499-4de0-9bff-60635b5b250c'}
# nprod/SyncAction - Secret Value: {'BogusToken':'989e9ab0-de1e-4a12-9bad-a7b531cda777'}


    # process_secret(aws_secrets, secret_name)
    # for i, secret in enumerate(secrets, 1):
    #     secret_name = secret['Name']
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