"""Read an exact AWS KMS key lifecycle without accessing its key material."""
from datetime import datetime, timedelta
import re
import time

from setrya.offboarding.inputs import InvalidReport, require

from .profiles import decode, fields, stamp

UUID_PATTERN = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
_KEY_ARN = re.compile(r"arn:aws:kms:([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+):([0-9]{12}):key/(" + UUID_PATTERN + r")")
_KEY_STATES = {"Creating", "Enabled", "Disabled", "PendingDeletion", "PendingImport", "PendingReplicaDeletion",
               "Unavailable", "Updating"}
_KEY_PROPERTIES = {"origin": "AWS_KMS", "manager": "CUSTOMER", "spec": "SYMMETRIC_DEFAULT",
                   "usage": "ENCRYPT_DECRYPT", "multi_region": False}


def key_parts(arn):
    match = _KEY_ARN.fullmatch(arn) if isinstance(arn, str) else None
    require(match is not None, "Use a single-Region KMS key ARN from the commercial AWS partition.")
    return match.groups()


def key_status(reading, arn, at):
    fields(reading, "status", ("metadata",))
    status = reading["status"]
    require(status in ("visible", "not-found", "unavailable"), "Invalid KMS observation.")
    if status != "visible":
        require("metadata" not in reading, "Unexpected KMS metadata.")
        return status
    data = reading.get("metadata")
    fields(data, "arn account key_id state enabled created_at origin manager spec usage multi_region")
    _, account, key_id = key_parts(arn)
    require(data["arn"] == arn and data["account"] == account and data["key_id"] == key_id
            and data["state"] in _KEY_STATES and data["enabled"] is (data["state"] == "Enabled")
            and stamp(data["created_at"]) <= at
            and data["multi_region"] is False
            and all(data[name] == expected for name, expected in _KEY_PROPERTIES.items()),
            "The exact key is ineligible for this verifier.")
    return data["state"]


def deletion_event(event, arn, captured, checked):
    fields(event, "event_id occurred_at account region arn source name type invoked_by")
    region, account, _ = key_parts(arn)
    require(isinstance(event["event_id"], str) and re.fullmatch(UUID_PATTERN, event["event_id"])
            and captured < stamp(event["occurred_at"]) <= checked
            and event["account"] == account and event["region"] == region and event["arn"] == arn
            and event["source"] == "kms.amazonaws.com" and event["name"] == "DeleteKey"
            and event["type"] == "AwsServiceEvent" and event["invoked_by"] == "AWS Internal",
            "CloudTrail does not identify a completed deletion for this exact KMS key.")


class AWSKeyObserver:
    """Restricted SDK call surface. The CLI always uses regional AWS endpoints."""

    def __init__(self, kms, cloudtrail, sts):
        self.kms = kms
        self.cloudtrail = cloudtrail
        self.sts = sts

    @classmethod
    def connect(cls, arn):
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise InvalidReport("Install setrya[crypto-aws] to query AWS KMS and CloudTrail.") from None
        region, _, _ = key_parts(arn)
        session = boto3.Session(region_name=region)
        require(session.get_partition_for_region(region) == "aws", "Use a commercial AWS KMS Region.")
        config = Config(connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 3, "mode": "standard"},
                        ignore_configured_endpoint_urls=True)
        clients = (session.client(service, region_name=region, config=config, verify=True)
                   for service in ("kms", "cloudtrail", "sts"))
        return cls(*clients)

    def account(self, arn):
        from botocore.exceptions import BotoCoreError, ClientError

        region, account, _ = key_parts(arn)
        if any(client.meta.region_name != region for client in (self.kms, self.cloudtrail, self.sts)):
            return None
        try:
            caller = self.sts.get_caller_identity()
        except (BotoCoreError, ClientError):
            return None
        return account if caller.get("Account") == account else None

    def describe(self, arn, at):
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            key = self.kms.describe_key(KeyId=arn)["KeyMetadata"]
            created = key["CreationDate"]
            require(isinstance(created, datetime), "Invalid key creation date.")
            result = {"status": "visible", "metadata": {
                "arn": key["Arn"], "account": key["AWSAccountId"], "key_id": key["KeyId"],
                "state": key["KeyState"], "enabled": key["Enabled"], "created_at": created.isoformat(), "origin": key["Origin"],
                "manager": key["KeyManager"], "spec": key["KeySpec"], "usage": key["KeyUsage"],
                "multi_region": key["MultiRegion"],
            }}
            key_status(result, arn, at)
            return result
        except ClientError as exc:
            if (exc.operation_name == "DescribeKey" and exc.response.get("Error", {}).get("Code") == "NotFoundException"
                    and exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 400):
                return {"status": "not-found"}
        except (BotoCoreError, InvalidReport, KeyError, TypeError, ValueError):
            pass
        return {"status": "unavailable"}

    def deletion(self, arn, captured, checked):
        from botocore.exceptions import BotoCoreError, ClientError

        start = max(captured, checked - timedelta(days=90) + timedelta(seconds=5))
        if start >= checked:
            return None
        params = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "DeleteKey"}],
                  "StartTime": start, "EndTime": checked, "MaxResults": 50}
        seen = set()
        try:
            for page_index in range(10):
                if page_index:
                    time.sleep(0.5)  # CloudTrail permits two Lookups per second per account and Region.
                page = self.cloudtrail.lookup_events(**params)
                for entry in page.get("Events", []):
                    event = _normalize_event(entry, arn, captured, checked)
                    if event is not None:
                        return event
                token = page.get("NextToken")
                if not token or token in seen:
                    break
                seen.add(token)
                params["NextToken"] = token
        except (BotoCoreError, ClientError):
            pass
        return None


def _normalize_event(entry, arn, captured, checked):
    try:
        raw = entry["CloudTrailEvent"]
        if not isinstance(raw, str) or len(raw) > 65_536:
            return None
        event = decode(raw.encode("utf-8"))
        _, account, _ = key_parts(arn)
        identity = event["userIdentity"]
        if (identity["accountId"] != account or event["requestParameters"] is not None
                or "errorCode" in event or "errorMessage" in event or event["eventID"] != entry["EventId"]
                or event["readOnly"] is not False or event["managementEvent"] is not True
                or event["eventCategory"] != "Management"
                or event["responseElements"] != {"keyId": arn}
                or sum(1 for resource in event["resources"] if resource == {
                    "accountId": account, "type": "AWS::KMS::Key", "ARN": arn}) != 1):
            return None
        result = {"event_id": event["eventID"], "occurred_at": event["eventTime"],
                  "account": event["recipientAccountId"], "region": event["awsRegion"], "arn": arn,
                  "source": event["eventSource"], "name": event["eventName"], "type": event["eventType"],
                  "invoked_by": identity["invokedBy"]}
        deletion_event(result, arn, captured, checked)
        return result
    except (ValueError, TypeError, KeyError, RecursionError):
        return None
