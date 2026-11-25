"""Sampled answer evidence must survive a late leak, an abstention and offline replay."""
from collections import Counter
from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from setrya.erasure import (
    AnswerJudges, Artifact, Marker, ModelDecision, ModelJudge, ReviewedAnswers, SharedCase,
    Stored, Subject, TextAnswer, run_shared,
)
from setrya.erasure import v3
from setrya.erasure.v3_receipt import derive, replay
from setrya.offboarding.inputs import InvalidReport


HOST = "cobalt-bridge.example"
SPOKEN = "the host is cobalt bridge dot example"
DATE = "October 18"
EMPTY = "No matching note."
SUBJECT = Subject("f" * 64, "test")
QUESTIONS = ("Which host?", "Which date?", "Where do we connect?", "When is launch?")
JUDGES = AnswerJudges(
    (Marker(HOST), ReviewedAnswers((HOST, SPOKEN), (DATE, EMPTY))),
    (Marker(DATE), ReviewedAnswers((DATE,), (HOST, SPOKEN, EMPTY))),
)


class Endpoint:
    def __init__(self):
        self.erased = False
        self.calls = Counter()
        self.leak = None

    def read(self, subject, caller, conversation, question):
        key = (self.erased, caller, question)
        self.calls[key] += 1
        if self.erased and self.leak:
            returned = self.leak(caller, question, self.calls[key])
            if returned is False:
                return None
        else:
            returned = None
        if returned is None:
            returned = DATE if question in QUESTIONS[1::2] else EMPTY if self.erased else HOST
        return TextAnswer(caller, conversation, "/ask", question, returned)

    def erase(self, subject):
        self.erased = True

    def inspect(self, subject, store, key):
        return Stored(key, not self.erased, not self.erased, False, None if self.erased else "1")


class SampledAnswers(unittest.TestCase):
    def setUp(self):
        self.app = Endpoint()
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name) / "case"
        self.case = SharedCase("ticket", "/ask", ("alice", "bob"), *QUESTIONS[:2],
                               (Artifact("notes", "1", "delete"),), judges=JUDGES,
                               target_variants=(QUESTIONS[2],), control_variants=(QUESTIONS[3],), model_backed=True)

    def run_case(self):
        result = run_shared(SUBJECT, case=self.case, application=self.app, output=self.out, mode="deletion")
        self.assertEqual(replay(self.out), result)
        return result, json.loads((self.out / "erasure-evidence.json").read_text())

    def test_fifth_read_of_indirect_question_leaks_despite_a_separate_missing_sample(self):
        def leak(caller, question, n):
            if caller == "bob" and question == QUESTIONS[2] and n == 5:
                return SPOKEN
            if caller == "alice" and question == QUESTIONS[0] and n == 1:
                return False
        self.app.leak = leak
        result, evidence = self.run_case()
        self.assertEqual(result["technical_verdict"], "FAIL")
        self.assertIn("bob recovered the erased finding at final read.", result["failures"])
        summary = result["answer_sampling"]
        self.assertEqual(summary["samples_per_question"], 3)
        self.assertEqual(summary["target_coverage"], "reviewed-answers")
        self.assertIs(result["lexical_only"], True)
        self.assertEqual(summary["stages"]["baseline"]["planned"], 24)
        self.assertEqual(summary["stages"]["immediate"]["observed"], 23)
        self.assertEqual(summary["stages"]["final"]["target_positive"], 1)
        self.assertEqual(self.app.calls[(True, "bob", QUESTIONS[2])], 6)
        self.assertFalse(any(word in json.dumps(evidence) for word in (SPOKEN, HOST, QUESTIONS[2])))

    def test_lexical_only_or_unreviewed_reply_cannot_be_proven_absent(self):
        self.case = replace(self.case, judges=AnswerJudges(Marker(HOST), Marker(DATE)))
        self.app.leak = lambda *_: SPOKEN
        result, _ = self.run_case()
        self.assertEqual(result["technical_verdict"], "NOT TESTED")
        self.assertEqual(result["answer_sampling"]["target_coverage"], "lexical-only")
        self.assertIs(result["lexical_only"], True)
        self.assertEqual(result["answer_sampling"]["stages"]["final"]["target_uncertain"], 24)

    def test_unrecognized_text_abstains_even_with_a_reviewed_answer_policy(self):
        self.app.leak = lambda c, q, n: "the old machine" if q == QUESTIONS[0] else None
        result, _ = self.run_case()
        self.assertEqual(result["technical_verdict"], "NOT TESTED")

    def test_positive_from_other_judge_takes_precedence_over_model_disagreement(self):
        def negative(_):
            return ModelDecision(False, "No semantic match.")
        self.case = replace(self.case, judges=AnswerJudges((Marker(HOST),
                            ModelJudge("rubric/v1", negative, paraphrase_aware=True)), Marker(DATE)))
        self.app.leak = lambda c, q, n: HOST if q == QUESTIONS[-1] and n == 2 else None
        result, _ = self.run_case()
        self.assertEqual(result["technical_verdict"], "FAIL")
        self.assertEqual(result["answer_sampling"]["target_coverage"], "paraphrase-aware")

    def test_list_judge_chain_reports_paraphrased_leak_from_model(self):
        def semantic(text):
            return ModelDecision(True, "The saved host is present.", text) if text in (HOST, SPOKEN) else ModelDecision(
                False, "The saved host is absent.")

        self.case = replace(self.case, judges=AnswerJudges(
            [Marker(HOST), ModelJudge("rubric/v1", semantic, paraphrase_aware=True)], [Marker(DATE)]))
        self.app.leak = lambda c, q, n: SPOKEN if q == QUESTIONS[0] and n == 2 else None
        result, _ = self.run_case()
        self.assertEqual(result["technical_verdict"], "FAIL")
        self.assertEqual(result["answer_sampling"]["target_coverage"], "paraphrase-aware")
        self.assertEqual(result["answer_sampling"]["control_coverage"], "lexical-only")
        self.assertIs(result["lexical_only"], False)

    def test_uncertain_model_vote_blocks_absence_after_lexical_negative(self):
        def uncertain(text):
            return ModelDecision(None, "The meaning is ambiguous.")
        self.case = replace(self.case, judges=AnswerJudges((Marker(HOST),
                            ModelJudge("rubric/v1", uncertain, paraphrase_aware=True)), Marker(DATE)))
        result, _ = self.run_case()
        self.assertEqual(result["technical_verdict"], "NOT TESTED")

    def test_replay_rejects_duplicate_sample_and_shortened_chain(self):
        result, e = self.run_case()
        self.assertEqual(result["technical_verdict"], "PASS")
        sampled_format = e["format"]
        e["format"] = "setrya.erasure.evidence.v3"
        chain = e.pop("journal_chain")
        producer = e.pop("provenance")
        with self.assertRaisesRegex(InvalidReport, "evidence format"):
            derive(e, "0" * 64)
        e["format"] = sampled_format
        e["journal_chain"] = chain
        e["provenance"] = producer
        rows = e["final"]["answers"]
        rows[1][1]["sample"] = 1
        with self.assertRaisesRegex(InvalidReport, "ordinal"):
            derive(e, "0" * 64)
        rows[1][1]["sample"] = 2
        rows[1][1]["judgments"]["target"].pop()
        with self.assertRaisesRegex(InvalidReport, "slots"):
            derive(e, "0" * 64)

    def test_invalid_plan_is_rejected_before_opening_the_output(self):
        for case in (replace(self.case, samples=0), replace(self.case, samples=True),
                     replace(self.case, samples=33), replace(self.case, judges=None),
                     replace(self.case, target_variants=(QUESTIONS[0],))):
            with self.subTest(case=case), self.assertRaises(InvalidReport):
                run_shared(SUBJECT, case=case, application=self.app, output=self.out, mode="deletion")
        self.assertFalse(self.out.exists())
        self.assertFalse(self.app.calls)

    def test_large_excerpt_plan_is_rejected_before_erasure_and_digest_keeps_a_late_failure(self):
        def judge(fact, role):
            def decide(text):
                present = fact in text
                return ModelDecision(present, "判定の理由。" * 125, fact if present else None)
            return tuple(ModelJudge(f"{role}/v{i}", decide, paraphrase_aware=True) for i in range(6))

        policy = AnswerJudges(judge(HOST, "host"), judge(DATE, "date"), capture="excerpt")
        self.case = replace(self.case, target_variants=(), control_variants=(), samples=32, judges=policy)
        self.app.leak = lambda caller, question, n: HOST if caller == "alice" and n == 60 else None
        with self.assertRaisesRegex(InvalidReport, "replay size budget"):
            run_shared(SUBJECT, case=self.case, application=self.app, output=self.out, mode="deletion")
        self.assertFalse(self.app.erased)
        self.assertFalse(self.app.calls)
        self.assertFalse(self.out.exists())

        self.case = replace(self.case, judges=replace(policy, capture="digest"))
        result, _ = self.run_case()
        self.assertEqual(result["technical_verdict"], "FAIL")
        self.assertGreater(result["answer_sampling"]["stages"]["final"]["target_positive"], 0)

    def test_stable_api_and_unmodified_github_actions_receipt_from_1_0_3(self):
        self.assertIs(v3.SharedCase, SharedCase)
        folder = Path(__file__).parent / "fixtures/erasure_v3_1_0_3"
        receipt = replay(folder)
        self.assertEqual(receipt["technical_verdict"], "PASS")
        self.assertNotIn("answer_sampling", receipt)
