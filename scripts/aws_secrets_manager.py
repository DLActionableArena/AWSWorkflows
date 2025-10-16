import os
import boto3
from botocore.exceptions import ClientError
import urllib3
import json

DEFAULT_AWS_REGION = "us-east-2"
DEFAULT_VAULT_PATH = "aws/services"
AWS_SECRET_MANAGER="secretsmanager"
AWS_SECURITY_TOKEN_SERVICE="sts"

CREATED_SECRETS =  "CreatedSecrets"
UPDATED_SECRETS =  "UpdatedSecrets"
UNMODIFIED_SECRETS = "UnmodifiedSecrets"
NEW_REPLICATION_SECRETS = "NewReplicationSecrets"

VAULT_AWS_SECRET_PATH = DEFAULT_VAULT_PATH if DEFAULT_VAULT_PATH.endswith("/") \
                                           else  f"{DEFAULT_VAULT_PATH}/"
VAULT_AWS_SECRET_PATH_LEN = len(VAULT_AWS_SECRET_PATH)

AWS_REGION = os.getenv("AWS_REGION", DEFAULT_AWS_REGION)
AWS_ROLE_TO_ASSUME = os.getenv("AWS_ROLE_TO_ASSUME")
AWS_FILTER_SECRET_NAME = os.getenv("AWS_FILTER_SECRET_NAME", "")
AWS_REPLICATE_REGIONS = os.getenv("AWS_REPLICATE_REGIONS", "").split(",") \
                        if len(os.getenv("AWS_REPLICATE_REGIONS", "")) > 0 else []
SIMULATION_MODE = os.getenv("SIMULATION_MODE", "False") == "True"
ENVIRONMENT = os.getenv("ENVIRONMENT", "DEV")

# Global variables
aws_client = None
aws_current_region = AWS_REGION
execution_stats = {
    CREATED_SECRETS: [],
    UPDATED_SECRETS: [],
    UNMODIFIED_SECRETS: [],
    NEW_REPLICATION_SECRETS: []
}
error_stats = {
  CREATED_SECRETS: [],
  UPDATED_SECRETS: [],
  NEW_REPLICATION_SECRETS: [],
}

# TODO -
#      - Simulation mode
#      - Environment execution support


def generate_execution_summary():
    """Generate an execution summary for display as the job summary"""

    created_secrets_count    = len(execution_stats[CREATED_SECRETS])
    updated_secrets_count    = len(execution_stats[UPDATED_SECRETS])
    unmodified_secrets_count = len(execution_stats[UNMODIFIED_SECRETS])
    replicated_secrets_count = len(execution_stats[NEW_REPLICATION_SECRETS])
    total_secrets_count      = created_secrets_count + \
                               updated_secrets_count + \
                               unmodified_secrets_count

    created_secrets_errors = len(error_stats[CREATED_SECRETS])
    updated_secrets_errors = len(error_stats[UPDATED_SECRETS])
    replicated_secrets_errors = len(error_stats[NEW_REPLICATION_SECRETS])

    execution_status = "Completed Successfully"
    error_report = "No Reported Errors"
    if  created_secrets_errors > 0 or\
        updated_secrets_errors > 0 or\
        replicated_secrets_errors > 0:
        error_report = f"""
            Newly Created: {created_secrets_errors}
            Existing Updated: {updated_secrets_errors}
            Newly Replicated: {replicated_secrets_errors}
        """
        execution_status = "Completed with errors, see the steps logs"

    report = f"""
    Secrets Counts:
        Total: {total_secrets_count}
        Newly Created: {created_secrets_count}
        Existing Updated: {updated_secrets_count}
        Existing Unmodified: {unmodified_secrets_count}
        Newly Replicated: {replicated_secrets_count}
    Errors Counts:
        {error_report}
    Simulation Mode: {SIMULATION_MODE}
    Execution Status: {execution_status}
    """

    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as fh:
        print(f'{report}', file=fh)

def replicate_secret_change_to_new_regions(secret_name, added_regions):
    """Replicate a secret change to all regions"""
    #   Required permissions:
    #       secretsmanager:ReplicateSecretToRegions
    #       if  encrypted with custom key: kms:Decrypt, kms:GenerateDataKey and kms:Encrypt
    try:
        aws_client.replicate_secret_to_regions(
            SecretId=secret_name,
            AddReplicaRegions=create_aws_secret_replicated_regions(added_regions)
        )
        print(f"Replicated secret {secret_name} to regions: {added_regions}")
        execution_stats[NEW_REPLICATION_SECRETS].append(secret_name)
    except Exception as e:
        print(f"Error replicating secret {secret_name}: {e}")

def get_secret_replicated_regions(secret_name):
    """Retrieves the regions a secret is replicated to"""
    try:
        # Include main to avoid it being considered as a replicated region
        replicated_regions = [aws_current_region]

        # Extract any currently defined replication regions for the secret name
        response = aws_client.describe_secret(SecretId=secret_name)
        if "ReplicationStatus" in response:
            for replica in response["ReplicationStatus"]:
                if "Region" in replica:
                    replicated_regions.append(replica["Region"])

    except aws_client.exceptions.ResourceNotFoundException:
        print(f"Unable to retrieve regions, secret {secret_name} not found.")
    except Exception as e:
        print(f"An error occurred retrieving secret {secret_name} regions: {e}")

    return replicated_regions

def process_secret_regions(secret_name):
    """Apply the request secrets change to newly configured regions"""
    # Retrieve all configured regions not already assigned to the secret name
    # And find any newly added ones
    replicated_regions = get_secret_replicated_regions(secret_name)
    added_regions = list(set(AWS_REPLICATE_REGIONS).difference(set(replicated_regions)))

    if len(added_regions) > 0:
        print(f"Secret {secret_name} has newly configured replication to regions: {added_regions}")
        replicate_secret_change_to_new_regions(secret_name, added_regions)

def update_aws_secret(secret_name, secret_value):
    """Update an AWS secret"""
    # Required permissions:
    #   secretsmanager:UpdateSecret
    try:
        aws_client.update_secret(
            SecretId=secret_name,
            SecretString=secret_value
        )
        print(f"Secret {secret_name} successfully updated.")
        execution_stats[UPDATED_SECRETS].append(secret_name)
    except aws_client.exceptions.ResourceExistsException:
        print(f"Secret {secret_name} already exists.")
        error_stats[UPDATED_SECRETS].append(secret_name)
    except Exception as e:
        print(f"Error updating secret {secret_name} : {e}")
        error_stats[UPDATED_SECRETS].append(secret_name)

def create_aws_secret_replicated_regions(replicate_regions):
    """Generate and returns a replication regions list"""
    regions = []

    for replicate_region in replicate_regions:
        region = {}
        region["Region"]=replicate_region.strip()
        regions.append(region)
        print(f"Adding region: {region}")
    print(f"Returning regions: {regions}")
    return regions

def create_aws_secret(secret_name, secret_value):
    """Create an AWS secret"""
    # Required permissions:
    #   secretsmanager:CreateSecret
    #   secretsmanager:TagResource (optional - If secret includes tags)
    #   secretsmanager:ReplicateSecretToRegions (optional - If secret includes replica regions)
    try:
        print(f"Adding AWS secret: {secret_name}")
        if len(AWS_REPLICATE_REGIONS) > 0:
            aws_client.create_secret(
                Name=secret_name,
                SecretString=secret_value,
                AddReplicaRegions=create_aws_secret_replicated_regions(AWS_REPLICATE_REGIONS)
            )
            execution_stats[NEW_REPLICATION_SECRETS].append(secret_name)
        else:
            aws_client.create_secret(
                Name=secret_name,
                SecretString=secret_value
            )
        print(f"Secret {secret_name} successfully created.")
        execution_stats[CREATED_SECRETS].append(secret_name)
    except aws_client.exceptions.ResourceExistsException:
        print(f"Secret {secret_name} already exists.")
        error_stats[CREATED_SECRETS].append(secret_name)
    except Exception as e:
        print(f"Error creating secret {secret_name} : {e}")
        error_stats[CREATED_SECRETS].append(secret_name)

def extract_secret_name(vault_secret_name):
    """Returns the secret name from the provided path"""
    secret_name = vault_secret_name
    if  len(vault_secret_name) > VAULT_AWS_SECRET_PATH_LEN and \
        vault_secret_name.startswith(VAULT_AWS_SECRET_PATH):
        secret_name = vault_secret_name[VAULT_AWS_SECRET_PATH_LEN:]

    return secret_name

def process_secrets(aws_secrets, vault_secret_name, vault_secret_value):
    """Process the specified secrets path and data"""
    # Convert the secret value to JSON string for change validation
    vault_secret_name_match =  extract_secret_name(vault_secret_name)
    req_aws_filtered_secret_name = AWS_FILTER_SECRET_NAME.strip()
    if  len(req_aws_filtered_secret_name) > 0 and \
        vault_secret_name_match != req_aws_filtered_secret_name:
        print(f"Skip secret name: {vault_secret_name_match} no match to filtered: {req_aws_filtered_secret_name}")
        return

    # Convert the value to JSON/string (sorted keys) for comparison with AWS value
    vault_secret_value_str = json.dumps(vault_secret_value, sort_keys=True)

    # Iterate through AWS Secrets to locate any match and update if found
    for aws_secret in aws_secrets.items():
        aws_secret_name  = aws_secret[0]
        aws_secret_value = aws_secret[1]

        # Process the secret if a name match is found
        if aws_secret_name == vault_secret_name_match:
            # Convert the value to JSON/string (sorted keys) for comparison with vault value
            aws_secret_value_str = json.dumps(aws_secret_value, sort_keys=True)

            if vault_secret_value_str != aws_secret_value_str:
                print(f"Value change detected for AWS secret with name {aws_secret_name}, updating")
                update_aws_secret(vault_secret_name_match, vault_secret_value_str)
            else:
                print(f"No change detected to AWS Secret name {vault_secret_name_match}")
                execution_stats[UNMODIFIED_SECRETS].append(vault_secret_name_match)

            # Possibly dispatch secret to newly configured regions
            process_secret_regions(vault_secret_name_match)
            return

    # Create a new AWS secret and possibly replicate to other regions
    create_aws_secret(vault_secret_name_match, vault_secret_value_str)

def get_secret_value(secret_name):
    """Retrieve a specific secret value from AWS Secrets Manager"""
    try:
        response = aws_client.get_secret_value(SecretId=secret_name)
        return response.get("SecretString", None)
    except Exception as e:
        print(f"Error retrieving secret value{secret_name}: {e}")
        return None

def get_specific_secret(secret_name):
    """Retrieve a specific AWS secret"""
    secret = {}
    try:
        print(f"Retrieving specific secret_name {secret_name}")
        secret_value = get_secret_value(secret_name)
        if secret_value:
            secret[secret_name] = json.loads(secret_value)
            print(f"Retrieved secret {secret_name} with value: {secret[secret_name]}")
        else:
            print(f"No value found for secret {secret_name}")
    except Exception as e:
        print(f"Error retrieving specific secret {secret_name}: {e}")
    return secret

def get_all_aws_secrets():
    """Retrieve all AWS secrets"""
    secrets = {}
    secrets_details = []
    paginator = aws_client.get_paginator("list_secrets")
    for page in paginator.paginate():
        secrets_details.extend(page.get("SecretList", []))

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
        "aws/services/app/Secrets" : {"BogusKey":"BogusSecret", "dumb-secret":"789"},
        "aws/services/app1/Secrets" : {"secret1":"value1a"},
        "aws/services/app2/Secrets" : {"secret2":"value2a"},
        "aws/services/nprod/SyncAction" : {"BogusToken": "989e9ab0-de1e-4a12-9bad-a7b531cda777"},
        "aws/services/nprod/AnotherAppSecret" : {"Secret": "47aaa505-4499-4de0-9baa-60635b5b2556", "Another secret": "86bbb505-4499-4de0-9bff-60635b5b250c"},
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

        # Extract the current region
        session = boto3.Session()
        aws_current_region = session.region_name

        # Suppress SSL warnings if needed
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        return True
    except Exception as e:
        print(f"Error initializing AWS client: {e}")
        return False

def main():
    """"Main function to demonstrate functionality"""
    initialize_clients()

    print(f"Clients initialized successfully for environment: {ENVIRONMENT}")

    req_aws_filtered_secret_name = AWS_FILTER_SECRET_NAME.strip()
    aws_secrets = get_specific_secret(req_aws_filtered_secret_name)\
                  if len(req_aws_filtered_secret_name) > 0\
                  else get_all_aws_secrets()
    process_mock_vault_data(aws_secrets)
    generate_execution_summary()

if __name__ == "__main__":
    main()