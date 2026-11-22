"""Evaluate the actual answer text locally and carry bounded reasons into replay."""
from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Callable

from setrya.offboarding.inputs import keys_match, require
from .journal import identifier


def _digest(text):
    return sha256(text.encode("utf-8")).hexdigest()


def _text(value, limit):
    return isinstance(value, str) and 0 < len(value) <= limit


def _hash(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


@dataclass(frozen=True)
class TextAnswer:
    """Identity from the serving response and its actual answer body."""
    caller: str
    conversation: str
    route: str
    question: str
    text: str


@dataclass(frozen=True)
class ModelDecision:
    """Use None for uncertainty. A positive decision needs a quote from the answer."""
    present: bool | None
    reason: str
    match: str | None = None


@dataclass(frozen=True)
class Marker:
    """Case-sensitive, literal substring."""
    value: str
    kind = "marker"

    def evaluate(self, text):
        return _local_decision(self.value if self.value in text else None)


@dataclass(frozen=True)
class Regex:
    """Trusted, application-authored Python expression. Empty matches do not identify a fact."""
    value: str
    kind = "regex"

    def __post_init__(self):
        require(_text(self.value, 1024), "Expected a bounded regex.")
        re.compile(self.value)

    def evaluate(self, text):
        return _local_decision(next((m.group() for m in re.finditer(self.value, text) if m.group()), None))


@dataclass(frozen=True)
class Entity:
    """A literal name, matched case-insensitively at word boundaries."""
    value: str
    kind = "entity"

    def evaluate(self, text):
        found = re.search(r"(?<!\w)" + re.escape(self.value) + r"(?!\w)", text, re.IGNORECASE)
        return _local_decision(found.group() if found else None)


def _local_decision(match):
    return ModelDecision(match is not None, "Matched the configured rule." if match else "No match for the configured rule.", match)


@dataclass(frozen=True)
class ModelJudge:
    """Application-supplied evaluator. The rule ID should identify the model and rubric revision."""
    value: str
    evaluate: Callable[[str], ModelDecision]
    paraphrase_aware: bool = False
    kind = "model"

    def __post_init__(self):
        identifier(self.value, "model and rubric ID")
        require(callable(self.evaluate) and type(self.paraphrase_aware) is bool, "Invalid model judge.")


@dataclass(frozen=True)
class ReviewedAnswers:
    """Judge reviewed whole replies. Unrecognized wording always abstains."""
    present: tuple[str, ...]
    absent: tuple[str, ...]
    kind = "reviewed"

    def __post_init__(self):
        for phrases in (self.present, self.absent):
            require(isinstance(phrases, tuple) and 1 <= len(phrases) <= 32
                    and all(_text(v, 1024) for v in phrases), "Supply bounded reviewed replies.")
        replies = self.present + self.absent
        require(len(set(replies)) == len(replies), "Reviewed replies must be distinct.")

    def evaluate(self, text):
        if text in self.present:
            return ModelDecision(True, "Reviewed whole reply contains the fact.", text)
        if text in self.absent:
            return ModelDecision(False, "Reviewed whole reply excludes the fact.")
        return ModelDecision(None, "Unrecognized whole reply.")


Judge = Marker | Regex | Entity | ModelJudge | ReviewedAnswers


def _chain(value):
    rules = value if isinstance(value, tuple) else (value,)
    require(1 <= len(rules) <= 8, "Supply one to eight answer judges per fact.")
    return rules


def _rule(judge):
    if isinstance(judge, ReviewedAnswers):
        return {"kind": "reviewed", "present_sha256": sorted(_digest(v) for v in judge.present),
                "absent_sha256": sorted(_digest(v) for v in judge.absent)}
    require(isinstance(judge, (Marker, Regex, Entity, ModelJudge)) and _text(judge.value, 1024),
            "Each answer judge needs a nonempty bounded rule.")
    rule = {"kind": judge.kind, "rule_sha256": _digest(judge.value)}
    if isinstance(judge, ModelJudge):
        rule.update(model_rule=judge.value, paraphrase_aware=judge.paraphrase_aware)
    return rule


def coverage(rules):
    if any(rule.get("paraphrase_aware") is True for rule in rules):
        return "paraphrase-aware"
    if any(rule["kind"] == "reviewed" for rule in rules):
        return "reviewed-answers"
    return "unconfirmed" if any(rule["kind"] == "model" for rule in rules) else "lexical-only"


def consensus(decisions, rules):
    if any(item and item["present"] is True for item in decisions):
        return True
    if all(item and item["present"] is False for item in decisions) and coverage(rules) in (
            "paraphrase-aware", "reviewed-answers"):
        return False
    return None


@dataclass(frozen=True)
class AnswerJudges:
    target: Judge | tuple[Judge, ...]
    control: Judge | tuple[Judge, ...]
    capture: str = "digest"

    def maximum_decision_bytes(self):
        """Upper bound on the JSON for all votes on one answer, including quoted Unicode."""
        total = 0
        for judge in (*_chain(self.target), *_chain(self.control)):
            total += 512  # Indented object, digests and fixed local rationale.
            if self.capture == "excerpt":
                # The JSON writer may encode one character as two six-byte escapes.
                if isinstance(judge, ReviewedAnswers):
                    total += max(len(json.dumps(reply[:256])) for reply in judge.present)
                elif isinstance(judge, Marker):
                    total += len(json.dumps(judge.value[:256]))
                elif isinstance(judge, Entity):
                    total += 12 * min(256, len(judge.value))
                else:
                    total += 12 * 256
                if isinstance(judge, ModelJudge):
                    total += 12 * 1024
        return total

    def spec(self):
        spec = {"capture": self.capture,
                "target": [_rule(judge) for judge in _chain(self.target)],
                "control": [_rule(judge) for judge in _chain(self.control)]}
        check_policy(spec, sampled=True)
        return spec

    def inspect(self, text, observe=None):
        require(isinstance(text, str) and len(text.encode("utf-8")) <= 65536, "Expected a bounded answer body.")
        result = {"answer_sha256": _digest(text)}
        for role in ("target", "control"):
            chain = _chain(getattr(self, role))
            decisions = []
            for judge in chain:
                def decide():
                    return self._decision(judge, text)
                decisions.append(decide() if observe is None else observe(role + "_judge", decide))
            result[role] = decisions
        return result

    def _decision(self, judge, text):
        decision = judge.evaluate(text)
        require(isinstance(decision, ModelDecision) and type(decision.present) in (bool, type(None))
                and _text(decision.reason, 1024), "A judge must supply a decision and bounded reason.")
        match = decision.match
        if decision.present is True:
            require(_text(match, 65536) and match in text, "A positive judge decision must quote the answer.")
        else:
            require(match is None, "An absent or uncertain fact cannot have a matching quote.")
        reason = decision.reason
        if self.capture == "digest" and isinstance(judge, ModelJudge):
            reason = "Model decision recorded; rationale withheld."
        return {"present": decision.present, "reason": reason,
                        "reason_sha256": _digest(decision.reason), "match_sha256": _digest(match) if match else None,
                        "excerpt": match[:256] if match and self.capture == "excerpt" else None}


def _check_rule(rule, sampled):
    require(isinstance(rule, dict), "Unknown answer judge.")
    if sampled and rule.get("kind") == "reviewed":
        require(keys_match(rule, ("kind", "present_sha256", "absent_sha256")), "Invalid reviewed rule.")
        present, absent = rule["present_sha256"], rule["absent_sha256"]
        for items in (present, absent):
            require(isinstance(items, list) and 1 <= len(items) <= 32 and all(_hash(v) for v in items)
                    and items == sorted(set(items)), "Invalid reviewed replies.")
        require(not set(present).intersection(absent), "Conflicting reviewed replies.")
        return
    require(rule.get("kind") in ("marker", "regex", "entity", "model"), "Unknown answer judge.")
    model = rule["kind"] == "model"
    fields = ["kind", "rule_sha256"]
    if model:
        fields += ["model_rule"]
        if sampled:
            fields += ["paraphrase_aware"]
    require(keys_match(rule, fields) and _hash(rule["rule_sha256"]), "Invalid answer judge rule.")
    if model:
        identifier(rule["model_rule"], "model and rubric ID")
        require(_digest(rule["model_rule"]) == rule["rule_sha256"], "Wrong model rule digest.")
        if sampled:
            require(type(rule["paraphrase_aware"]) is bool, "Declare model judge paraphrase coverage.")


def check_policy(policy, sampled=False):
    require(keys_match(policy, ("target", "control", "capture")) and policy["capture"] in ("excerpt", "digest"),
            "Invalid answer judge policy.")
    for role in ("target", "control"):
        rules = policy[role] if sampled else [policy[role]]
        require(isinstance(rules, list) and 1 <= len(rules) <= 8, "Invalid judge chain.")
        for rule in rules:
            _check_rule(rule, sampled)
        require(all(rule not in rules[:i] for i, rule in enumerate(rules)), "Duplicate judge rule.")


def _check_decision(item, rule, capture, answer_hash):
    if item is None:
        return
    require(keys_match(item, ("present", "reason", "reason_sha256", "match_sha256", "excerpt"))
            and type(item["present"]) in (bool, type(None)) and _text(item["reason"], 1024)
            and _hash(item["reason_sha256"]), "Invalid judged fact.")
    present, excerpt = item["present"], item["excerpt"]
    require((_hash(item["match_sha256"]) if present is True else item["match_sha256"] is None)
            and (_text(excerpt, 256) if present is True and capture == "excerpt" else excerpt is None),
            "Inconsistent matched answer evidence.")
    if present is True and rule["kind"] == "marker":
        require(item["match_sha256"] == rule["rule_sha256"], "Exact marker differs from its matched text.")
    if rule["kind"] == "reviewed":
        expected = None
        if answer_hash in rule["present_sha256"]:
            expected = True
        elif answer_hash in rule["absent_sha256"]:
            expected = False
        require(present is expected and (present is not True or item["match_sha256"] == answer_hash),
                "Reviewed decision differs from the recorded whole reply.")
    elif rule["kind"] != "model":
        require(type(present) is bool and item["reason"] == _local_decision("match" if present else None).reason,
                "Invalid deterministic judge decision.")
    if rule["kind"] == "model" and capture == "digest":
        require(item["reason"] == "Model decision recorded; rationale withheld.", "Unexpected private model rationale.")
    else:
        require(_digest(item["reason"]) == item["reason_sha256"], "Invalid answer rationale digest.")
    if excerpt and len(excerpt) < 256:
        require(_digest(excerpt) == item["match_sha256"], "Invalid answer quote digest.")


def check_observation(row, policy, sampled=False):
    observed = row["judgments"]
    require(keys_match(observed, ("target", "control", "answer_sha256")) and _hash(observed["answer_sha256"]),
            "Missing judged answer digest.")
    for role in ("target", "control"):
        rules = policy[role] if sampled else [policy[role]]
        decisions = observed[role] if sampled else [observed[role]]
        require(isinstance(decisions, list) and len(decisions) == len(rules), "Missing judge slots.")
        for rule, decision in zip(rules, decisions):
            _check_decision(decision, rule, policy["capture"], observed["answer_sha256"])
        if sampled:
            expected = consensus(decisions, rules)
        else:
            expected = (decisions[0] or {}).get("present")
        require(row[role + "_present"] is expected, "Fact flag differs from its recorded judge decisions.")
