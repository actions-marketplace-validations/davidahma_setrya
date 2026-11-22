from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import shutil
import sqlite3
import subprocess
import sys
import unittest

try:
    import pytest
except ImportError as exc:
    raise unittest.SkipTest("requires pytest") from exc

from setrya.casework._crypto_aws import AWSKeyObserver
from setrya.casework.crypto_erasure import capture, observe
from setrya.offboarding.inputs import InvalidReport
from setrya.receipts import replay

ACCOUNT = "111122223333"
REGION = "us-east-1"
ARN_PREFIX = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/"
TARGET = ARN_PREFIX + "11111111-1111-1111-1111-111111111111"
CONTROL = ARN_PREFIX + "22222222-2222-2222-2222-222222222222"
EVENT = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
CAPTURED = datetime(2026, 11, 1, tzinfo=timezone.utc)
CHECKED = CAPTURED + timedelta(days=8)
DELETED = CHECKED - timedelta(minutes=30)
SUBJECT, RETAINED, OTHER = "1" * 64, "2" * 64, "3" * 64
RESIDUAL, ABSENT, CONTROL_COPY, NEW = "a" * 64, "b" * 64, "c" * 64, "d" * 64


def _message(*arns, last=0):
    def sized(data):
        return len(data).to_bytes(2, "big") + data

    edks = b"".join(sized(b"aws-kms") + sized(arn.encode()) + sized(b"synthetic-edk") for arn in arns)
    return (b"\x02\x04\x78" + b"\x00" * 32 + sized(b"") + len(arns).to_bytes(2, "big") + edks
            + b"\x01" + b"\x00" * 4 + b"\x00" * 48 + b"\x00" * 35 + bytes([last]))


def _event(*, arn=TARGET, when=DELETED, **extras):
    event = {"eventVersion": "1.09", "eventName": "DeleteKey", "eventSource": "kms.amazonaws.com",
             "eventTime": when.isoformat(), "userIdentity": {"accountId": ACCOUNT, "invokedBy": "AWS Internal"},
             "awsRegion": REGION, "requestParameters": None, "responseElements": {"keyId": arn},
             "eventID": EVENT, "readOnly": False, "managementEvent": True, "eventCategory": "Management",
             "resources": [{"ARN": arn, "type": "AWS::KMS::Key", "accountId": ACCOUNT}],
             "eventType": "AwsServiceEvent", "recipientAccountId": ACCOUNT, **extras}
    return {"EventId": EVENT, "EventName": "DeleteKey", "EventSource": "kms.amazonaws.com",
            "EventTime": when, "CloudTrailEvent": json.dumps(event)}


def _metadata(arn, state="Enabled", **extras):
    return {"KeyMetadata": {"Arn": arn, "AWSAccountId": ACCOUNT, "KeyId": arn.split("/")[-1], "KeyState": state,
                            "CreationDate": CAPTURED - timedelta(days=40), "Origin": "AWS_KMS", "KeyManager": "CUSTOMER",
                            "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "MultiRegion": False,
                            "Enabled": state == "Enabled", **extras}}


@pytest.fixture
def aws():
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    session = boto3.Session(aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name=REGION)
    observer = AWSKeyObserver(*(session.client(name) for name in ("kms", "cloudtrail", "sts")))
    stubs = [Stubber(client) for client in (observer.kms, observer.cloudtrail, observer.sts)]
    with ExitStack() as resources:
        for stub in stubs:
            resources.enter_context(stub)
        yield observer, *stubs
        for stub in stubs:
            stub.assert_no_pending_responses()


@pytest.fixture
def fixture(tmp_path):
    path = tmp_path / "copies.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE copies (copy_ref TEXT PRIMARY KEY, subject_ref TEXT NOT NULL, ciphertext BLOB NOT NULL)")
        db.executemany("INSERT INTO copies VALUES (?, ?, ?)", [(RESIDUAL, SUBJECT, _message(TARGET)),
                       (ABSENT, SUBJECT, _message(TARGET)), (CONTROL_COPY, RETAINED, _message(CONTROL))])
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"format": "setrya.crypto-inventory.v1", "subject_ref": SUBJECT,
                                    "retained_ref": RETAINED, "key_arn": TARGET, "retained_key_arn": CONTROL,
                                    "owner": "platform", "recovery_scope": "exclusive-kms-key",
                                    "stores": {"snapshots": {"database": "copies.db", "table": "copies"}}}))
    return path, inventory, tmp_path / "capture.json", tmp_path / "receipt"


def _identity(sts, account=ACCOUNT):
    sts.add_response("get_caller_identity", {"Account": account, "UserId": "synthetic",
                                             "Arn": f"arn:aws:iam::{account}:role/reader"})


def _capture(aws, fixture):
    observer, kms, _, sts = aws
    _identity(sts)
    kms.add_response("describe_key", _metadata(TARGET), {"KeyId": TARGET})
    kms.add_response("describe_key", _metadata(CONTROL), {"KeyId": CONTROL})
    _, inventory, manifest, _ = fixture
    pin = capture(inventory_path=inventory, output=manifest, observer=observer, now=CAPTURED)
    assert sha256(manifest.read_bytes()).hexdigest() == pin
    return pin


def _verify(aws, fixture, pin, *, state="NotFoundException", event=None, account=ACCOUNT, key_control="Enabled"):
    observer, kms, cloudtrail, sts = aws
    if account == ACCOUNT:
        if state in ("NotFoundException", "AccessDeniedException"):
            kms.add_client_error("describe_key", service_error_code=state, http_status_code=400,
                                 expected_params={"KeyId": TARGET})
        else:
            kms.add_response("describe_key", _metadata(TARGET, state), {"KeyId": TARGET})
        kms.add_response("describe_key", _metadata(CONTROL, key_control), {"KeyId": CONTROL})
        if state == "NotFoundException" and key_control == "Enabled":
            cloudtrail.add_response("lookup_events", {"Events": [event] if event else []}, {
                "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "DeleteKey"}],
                "StartTime": CAPTURED, "EndTime": CHECKED, "MaxResults": 50,
            })
    _identity(sts, account)
    _, inventory, manifest, output = fixture
    return observe(inventory_path=inventory, manifest_path=manifest, expect_manifest=pin, output=output,
                   observer=observer, now=CHECKED)


def test_completed_destruction_and_physical_absence_are_distinct(aws, fixture):
    pin = _capture(aws, fixture)
    db_path, _, _, output = fixture
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM copies WHERE copy_ref = ?", (ABSENT,))
    db_before = db_path.read_bytes()
    receipt = _verify(aws, fixture, pin, event=_event())
    assert receipt["technical_verdict"] == "PASS"
    assert receipt["key_status"] == "deleted"
    assert receipt["key_event"] == {"event_id": EVENT, "occurred_at": DELETED.isoformat()}
    assert {r["key_sha256"]: r["status"] for r in receipt["copies"]} == {RESIDUAL: "crypto-erased", ABSENT: "absent"}
    assert db_path.read_bytes() == db_before
    assert replay(output) == receipt
    from setrya.casework.receipt_summary import receipt_summary

    for audience in ("engineer", "reviewer", "customer"):
        rendered = receipt_summary(output, audience=audience)
        assert "crypto-erased" in rendered and "absent" in rendered
    raw = (output / "observation-evidence.json").read_bytes()
    assert b"synthetic-edk" not in raw and SUBJECT.encode() not in raw and b"copies.db" not in raw
    event_text = DELETED.isoformat().encode()
    (output / "observation-evidence.json").write_bytes(raw.replace(event_text, CAPTURED.isoformat().encode()))
    with pytest.raises(InvalidReport, match="completed deletion"):
        replay(output)


@pytest.mark.parametrize("state,event,account,key_control", [
    ("PendingDeletion", None, ACCOUNT, "Enabled"),
    ("Disabled", None, ACCOUNT, "Enabled"),
    ("AccessDeniedException", None, ACCOUNT, "Enabled"),
    ("NotFoundException", None, ACCOUNT, "Enabled"),
    ("NotFoundException", _event(arn=CONTROL), ACCOUNT, "Enabled"),
    ("NotFoundException", _event(when=CAPTURED), ACCOUNT, "Enabled"),
    ("NotFoundException", _event(awsRegion="us-west-2"), ACCOUNT, "Enabled"),
    ("NotFoundException", _event(eventName="ScheduleKeyDeletion"), ACCOUNT, "Enabled"),
    ("NotFoundException", _event(errorCode="AccessDenied"), ACCOUNT, "Enabled"),
    ("NotFoundException", _event(), "999988887777", "Enabled"),
    ("NotFoundException", _event(), ACCOUNT, "Disabled"),
])
def test_ambiguous_provider_observations_leave_open_items(aws, fixture, state, event, account, key_control):
    pin = _capture(aws, fixture)
    receipt = _verify(aws, fixture, pin, state=state, event=event, account=account, key_control=key_control)
    assert receipt["technical_verdict"] == "NOT TESTED"
    assert receipt["review_status"] == "OPEN_ITEMS"
    assert receipt["key_status"] == "unproven"
    assert "key_event" not in receipt
    assert all(row["status"] == "unknown" for row in receipt["copies"])
    assert receipt["open_items"]


def test_enabled_key_fails(aws, fixture):
    pin = _capture(aws, fixture)
    receipt = _verify(aws, fixture, pin, state="Enabled")
    assert receipt["technical_verdict"] == "FAIL"
    assert {r["status"] for r in receipt["copies"]} == {"recoverable"}


@pytest.mark.parametrize("change", ["rekey", "changed-bytes", "new-copy", "retag", "lost-control"])
def test_capture_does_not_certify_changed_or_unreadable_copies(aws, fixture, change):
    pin = _capture(aws, fixture)
    with sqlite3.connect(fixture[0]) as db:
        if change == "new-copy":
            db.execute("INSERT INTO copies VALUES (?, ?, ?)", (NEW, SUBJECT, _message(TARGET)))
        elif change == "retag":
            db.execute("UPDATE copies SET subject_ref = ? WHERE copy_ref = ?", (OTHER, RESIDUAL))
        elif change == "lost-control":
            db.execute("DELETE FROM copies WHERE copy_ref = ?", (CONTROL_COPY,))
        else:
            ciphertext = _message(CONTROL) if change == "rekey" else _message(TARGET, last=11)
            db.execute("UPDATE copies SET ciphertext = ? WHERE copy_ref = ?", (ciphertext, RESIDUAL))
    receipt = _verify(aws, fixture, pin, event=_event())
    assert receipt["technical_verdict"] == "NOT TESTED"
    assert any(r["status"] == "unknown" for r in receipt["copies"])
    if change != "new-copy":
        assert next(r["status"] for r in receipt["copies"] if r["key_sha256"] == RESIDUAL) == "unknown"


def test_alt_wrapping_key_is_ineligible_for_capture(aws, fixture):
    with sqlite3.connect(fixture[0]) as db:
        db.execute("UPDATE copies SET ciphertext = ? WHERE copy_ref = ?", (_message(TARGET, CONTROL), RESIDUAL))
    with pytest.raises(InvalidReport, match="single AWS KMS encrypted data key"):
        _capture(aws, fixture)
    assert not fixture[2].exists()


def test_non_kms_origin_cannot_be_captured(aws, fixture):
    observer, kms, _, sts = aws
    _identity(sts)
    kms.add_response("describe_key", _metadata(TARGET, Origin="EXTERNAL"), {"KeyId": TARGET})
    kms.add_response("describe_key", _metadata(CONTROL), {"KeyId": CONTROL})
    _, inventory, manifest, _ = fixture
    with pytest.raises(InvalidReport, match="eligible enabled AWS KMS keys"):
        capture(inventory_path=inventory, output=manifest, observer=observer, now=CAPTURED)
    assert not manifest.exists()


def test_aws_connector_ignores_custom_service_endpoints(monkeypatch):
    pytest.importorskip("boto3")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://fixture.invalid")
    monkeypatch.setenv("AWS_ENDPOINT_URL_KMS", "https://fixture.invalid")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic")
    observer = AWSKeyObserver.connect(TARGET)
    for client in (observer.kms, observer.cloudtrail, observer.sts):
        assert client.meta.region_name == REGION
        assert client.meta.endpoint_url.endswith(".amazonaws.com")


def test_inventory_and_baseline_pins_are_required_before_an_aws_call(aws, fixture):
    pin = _capture(aws, fixture)
    _, inventory, manifest, output = fixture
    args = {"inventory_path": inventory, "manifest_path": manifest, "output": output, "observer": aws[0], "now": CHECKED}
    with pytest.raises(InvalidReport, match="independently pinned"):
        observe(**args, expect_manifest="a" * 64)
    inventory.write_bytes(inventory.read_bytes() + b"\n")
    with pytest.raises(InvalidReport, match="different ciphertext inventory"):
        observe(**args, expect_manifest=pin)
    assert not output.exists()


def test_receipt_authenticates_offline_with_cosign(aws, fixture, tmp_path, monkeypatch):
    if shutil.which("cosign") is None:
        pytest.skip("requires Cosign")
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    pin = _capture(aws, fixture)
    _verify(aws, fixture, pin, event=_event())
    key = tmp_path / "signer"
    bundle = tmp_path / "crypto.sig"
    subprocess.run(["cosign", "generate-key-pair", "--output-key-prefix", str(key)], check=True)
    common = ["--receipt", str(fixture[3] / "erasure-receipt.json"), "--bundle", str(bundle)]
    cli = [sys.executable, "-m", "setrya"]
    subprocess.run([*cli, "erasure", "sign", *common, "--key", str(key.with_suffix(".key"))], check=True)
    subprocess.run([*cli, "verify", *common, "--key", str(key.with_suffix(".pub"))], check=True)
