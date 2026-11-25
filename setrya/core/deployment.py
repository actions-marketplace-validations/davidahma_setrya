"""Replay observed HTTP deployment identity and apply a reviewer's independent pin."""

import re
from ipaddress import ip_address
from urllib.parse import urlsplit

from .inputs import InvalidReport, keys_match, read_json, require
from .provenance import _DIGEST, _matches

FORMAT = "setrya.deployment-record.v1"
_ENVIRONMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_BUILD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SIGNALS = ("origin", "tls_sha256", "build_id")


def valid_build(value):
    return _matches(_BUILD, value)


def https_origin(value):
    """Accept one canonical HTTPS origin without credentials, paths or query data."""
    require(isinstance(value, str) and len(value) <= 270 and value.isascii()
            and all(32 < ord(letter) < 127 for letter in value), "Expected a canonical HTTPS deployment origin.")
    try:
        parts = urlsplit(value)
        host, port = parts.hostname or "", parts.port
    except ValueError:
        raise InvalidReport("Expected a canonical HTTPS deployment origin.") from None
    require(host and parts.scheme == "https" and port != 0, "Expected a canonical HTTPS deployment origin.")
    try:
        address = ip_address(host)
    except ValueError:
        require(len(host) <= 253 and all(_HOST_LABEL.fullmatch(label) for label in host.split("."))
                and not host.split(".")[-1].isdigit(), "Expected a valid HTTPS deployment hostname.")
        authority = host
    else:
        require("%" not in host, "Expected an HTTPS address without an interface or zone.")
        authority = f"[{address}]" if address.version == 6 else str(address)
    if port not in (None, 443):
        authority += f":{port}"
    require(value == f"https://{authority}", "Expected a canonical HTTPS deployment origin.")
    return value


def validate_record(value):
    require(keys_match(value, ("format", "environment", *_SIGNALS)) and value["format"] == FORMAT
            and _matches(_ENVIRONMENT, value["environment"]) and valid_build(value["build_id"])
            and _matches(_DIGEST, value["tls_sha256"]), "Invalid expected deployment record.")
    https_origin(value["origin"])
    return value


def read_pin(path):
    if path is None:
        return None
    value, _ = read_json(path, "expected deployment")
    return validate_record(value)


def validate_binding(binding):
    require(keys_match(binding, ("record", "behavior_sha256", "deployment_sha256", "status"))
            and _matches(_DIGEST, binding["behavior_sha256"])
            and _matches(_DIGEST, binding["deployment_sha256"])
            and binding["status"] in ("verified", "unverified"), "Invalid deployment binding.")
    validate_record(binding["record"])
    return binding


def check_pin(binding, expected_deployment):
    if expected_deployment is not None:
        expected = validate_record(expected_deployment)
        require(binding is not None and validate_binding(binding)["status"] == "verified" and binding["record"] == expected,
                "Receipt does not verify the independently expected deployment.")


def verify_pin(receipt, expected_deployment):
    check_pin(receipt.get("deployment"), expected_deployment)
    return receipt


def matches(observation, record):
    return observation is not None and all(observation[key] == record[key] for key in _SIGNALS)


def _validate_observation(value):
    require(keys_match(value, _SIGNALS)
            and (value["tls_sha256"] is None or _matches(_DIGEST, value["tls_sha256"]))
            and (value["build_id"] is None or value["tls_sha256"] is not None and valid_build(value["build_id"])),
            "Invalid response deployment observation.")
    https_origin(value["origin"])


def derive(binding, evidence, source):
    """Validate and project transport observations in the order of the recorded answers."""
    require(keys_match(binding, ("record", "behavior_sha256", "deployment_sha256", "reads", "erase")),
            "Invalid HTTP deployment evidence.")
    record = validate_record(binding["record"])
    behavior, deployment = binding["behavior_sha256"], binding["deployment_sha256"]
    require(_matches(_DIGEST, behavior) and _matches(_DIGEST, deployment)
            and source["application"]["execution"] == "http-case"
            and evidence["mode"] == "deletion" and evidence["case"]["sampling"]["source"] == "answer-text"
            and any(row["role"] == "entrypoint" and row["sha256"] == behavior for row in source["test_files"])
            and any(row["role"] == "test" and row["sha256"] == deployment for row in source["test_files"]),
            "HTTP deployment inputs differ from producer fingerprints.")
    answers = [answer for phase in ("baseline", "immediate", "final")
               if evidence[phase] is not None for answer in evidence[phase]["answers"]]
    observed = binding["reads"]
    require(isinstance(observed, list) and len(observed) == len(answers),
            "Expected one deployment observation per answer attempt.")
    verified = True
    for observation, answer in zip(observed, answers, strict=True):
        _validate_observation(observation)
        matched = matches(observation, record)
        require(matched or answer is None, "Answer evidence came from an unverified deployment.")
        verified = verified and matched
    erase = binding["erase"]
    if erase is not None:
        _validate_observation(erase)
        verified = verified and matches(erase, record)
    require(evidence["erased"] is not True or matches(erase, record),
            "Completed erasure does not bind the expected deployment.")
    if evidence["erased"] is not None or erase is not None:
        n_baseline = len(evidence["baseline"]["answers"])
        require(all(matches(read, record) for read in observed[:n_baseline]),
                "Erasure was attempted before the baseline deployment was verified.")
    return {"record": record, "behavior_sha256": behavior, "deployment_sha256": deployment,
            "status": "verified" if verified else "unverified"}
