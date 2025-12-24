import boto3
import csv
from datetime import datetime, timezone

#functions------------------------------------------

#calculates keys age
def get_key_age(creation_date):
    now = datetime.now(timezone.utc)
    return (now - creation_date).days


#Evaluate KMS key rotation compliance.
def check_kms_rotation_compliance(key_manager, rotation_enabled, rotation_period_days):

    # AWS-managed keys
    if key_manager == "AWS":
        return "PASS (AWS-managed)"

    # Customer-managed keys
    if not rotation_enabled:
        return "FAIL (Rotation disabled)"

    if rotation_period_days != "N/A" and rotation_period_days <= 90:
        return "PASS"

    return f"FAIL (Rotation period {rotation_period_days} days > 90)"
"""
    Policy logic: (above function)
    - AWS-managed keys are auto-pass
    - Customer-managed keys must have rotation enabled
    - Rotation period must be <= 90 days (configurable policy)
"""

#SCRIPT---------------------------------------------------

# Initialize KMS client - aws credentials already configured in the local env
kms = boto3.client("kms")

# Get the list of keys
response = kms.list_keys() 
keys = response["Keys"]

#list to store required key details
results =[]

for key in keys:
    key_id = key["KeyId"]

    #get the key details
    response_meta_data = kms.describe_key(KeyId=key_id)
    meta = response_meta_data["KeyMetadata"]

    nextRotationDate = "N/A"
    rotationDays = "N/A"
    rotationEnabled = False

    try:
        rotation = kms.get_key_rotation_status(KeyId=key_id)

        rotationEnabled = rotation["KeyRotationEnabled"]
    
        #getting rotation details
        if (rotationEnabled == True):
            nextRotationDate = rotation["NextRotationDate"]
            rotationDays = rotation["RotationPeriodInDays"]
    
    except Exception as e:
        print(f"[ERROR] Failed to get rotation status for key {key_id}: {e}")

    #calling age and compliance check function

    age = get_key_age(meta["CreationDate"])
    
    compliance_status = check_kms_rotation_compliance(
    meta["KeyManager"],
    rotationEnabled,
    rotationDays
    )


    results.append({
        "KeyId": meta["KeyId"],
        "KeyState": meta["KeyState"],
        "KeyManager":meta["KeyManager"],
        "RotationEnabled": rotationEnabled,
        "KeyCreationDate":meta["CreationDate"],
        "KeyAge": age,
        "NextRotationDate" : nextRotationDate,
        "RotationPeriodInDays": rotationDays,
        "ComplianceStatus": compliance_status
                })

with open("kms_key_compliance_report.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

print("KMS Key Compliance Report Generated")