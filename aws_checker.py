import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError


def validate_ses_account(access_key, secret_key, region="us-east-1"):
    """
    Validate AWS SES account credentials and fetch sending limits and health.
    :param access_key: AWS access key ID
    :param secret_key: AWS secret access key
    :param region: AWS region (default: us-east-1)
    :return: Dictionary with SES account health and sending limits if valid, None otherwise
    """
    try:
        # Create a session with the provided credentials
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )

        # Use the session to create an SESv2 client
        sesv2_client = session.client("sesv2")
        
        # Fetch account health and sending limits
        account_info = sesv2_client.get_account()
        sending_limits = account_info.get("SendQuota", {})
        reputation_metrics_enabled = account_info.get("Details", {}).get("ReputationMetricsEnabled", False)
        dedicated_ip_auto_warmup_enabled = account_info.get("Details", {}).get("DedicatedIpAutoWarmupEnabled", False)
        print(f"[+] SES Account Valid - Sending Limits: {sending_limits}")
        print(f"[+] Reputation Metrics Enabled: {reputation_metrics_enabled}")
        print(f"[+] Dedicated IP Auto Warm-Up Enabled: {dedicated_ip_auto_warmup_enabled}")

        # Return account details
        return {
            "access_key": access_key,
            "region": region,
            "sending_limits": sending_limits,
            "reputation_metrics_enabled": reputation_metrics_enabled,
            "dedicated_ip_auto_warmup_enabled": dedicated_ip_auto_warmup_enabled,
        }
    except (NoCredentialsError, PartialCredentialsError):
        print(f"[-] Invalid AWS credentials: {access_key}")
    except ClientError as e:
        print(f"[!] AWS Client Error: {e}")
    except Exception as e:
        print(f"[!] Unknown error: {e}")
    return None


def save_valid_credentials(account_details):
    """
    Save validated AWS SES account details to a file.
    :param account_details: Dictionary containing validated account details
    """
    with open("valid_aws_ses_credentials.txt", "a") as log_file:
        log_file.write("==== Valid AWS SES Credentials ====\n")
        log_file.write(f"Access Key: {account_details['access_key']}\n")
        log_file.write(f"Region: {account_details['region']}\n")
        log_file.write(f"Sending Limits: {account_details['sending_limits']}\n")
        log_file.write(f"Reputation Metrics Enabled: {account_details['reputation_metrics_enabled']}\n")
        log_file.write(f"Dedicated IP Auto Warm-Up Enabled: {account_details['dedicated_ip_auto_warmup_enabled']}\n\n")
    print(f"[+] Saved valid credentials: {account_details['access_key']}")


def begin_check(credentials_string, to=None, site=None):
    """
    Process AWS credentials for SES validation.
    :param credentials_string: String in the format 'access_key:secret_key:region'
    :param to: Optional, for logging or notification
    :param site: Optional, for logging or tracking
    """
    try:
        # Split the credentials string
        parts = credentials_string.split(":")
        if len(parts) != 3:
            print(f"[-] Invalid credentials format: {credentials_string}")
            return False

        access_key, secret_key, region = parts
        # Validate the SES account
        account_details = validate_ses_account(access_key, secret_key, region)
        if account_details:
            save_valid_credentials(account_details)
            return True
        return False
    except Exception as e:
        print(f"[!] Error in begin_check: {e}")
        return False


if __name__ == "__main__":
    # Example usage
    test_credentials = "AKIAEXAMPLE:abc123example:us-east-1"
    begin_check(test_credentials)
