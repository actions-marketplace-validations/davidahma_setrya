"""Import copy observations from one bounded OTLP/JSON trace export."""

import json
import re

from setrya.offboarding.inputs import read_regular_bytes, require, unique_fields

from .journal_merge import MAX_BYTES, MAX_EVENTS

EVENT = "setrya.copy.v1"
_SEQUENCE = "setrya_sequence"
_ATTRIBUTES = {
    "setrya_subject", "setrya_classification", "setrya_run", "setrya_producer", _SEQUENCE,
    "store", "copy_key", "source", "action", "observed_at", "details_json",
    "setrya_turn", "setrya_initiator", "setrya_agent", "setrya_on_behalf_of", "setrya_parent_turn",
}


def _children(value, name, *, required=False):
    require(isinstance(value, dict), "Invalid OTLP trace container.")
    result = value.get(name, None if required else [])
    require(isinstance(result, list), f"Expected an OTLP {name} array.")
    return result


def _attributes(event):
    attributes = {}
    keys = set()
    for attribute in _children(event, "attributes", required=True):
        require(isinstance(attribute, dict) and isinstance(attribute.get("key"), str),
                "Invalid OTLP event attribute.")
        key = attribute["key"]
        require(key not in keys, "Duplicate OTLP event attribute.")
        keys.add(key)
        if key not in _ATTRIBUTES:
            continue
        value = attribute.get("value")
        require(isinstance(value, dict) and len(value) == 1, "Expected one OTLP attribute value.")
        if key == _SEQUENCE:
            seq = value.get("intValue")
            if isinstance(seq, str) and re.fullmatch(r"[0-9]{1,19}", seq):
                seq = int(seq)
            require(type(seq) is int and 0 < seq < 2**63, "Invalid OTLP event sequence.")
            attributes[key] = seq
        else:
            text = value.get("stringValue")
            require(isinstance(text, str), "Expected an OTLP string attribute.")
            attributes[key] = text
    return attributes


def read_otlp(path):
    """Read OTLP JSON and discard all telemetry outside the copy-event attributes."""
    raw = read_regular_bytes(path, "OTLP trace export", MAX_BYTES)
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
    events = []
    for resource in _children(document, "resourceSpans", required=True):
        for scope in _children(resource, "scopeSpans"):
            for span in _children(scope, "spans"):
                for event in _children(span, "events"):
                    require(isinstance(event, dict), "Invalid OTLP span event.")
                    if event.get("name") != EVENT:
                        continue
                    require(len(events) < MAX_EVENTS, "OTLP export exceeds the copy-event limit.")
                    events.append(_attributes(event))
    require(events, "No setrya.copy.v1 events found in the OTLP export.")
    return events
