"""Exact, model-free counterexamples to overstrong agreement interpretations."""

import argparse
from fractions import Fraction as F
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    # v*=0. Actor is fair; constructor sees actor and verifies against an exact
    # independent certificate, retaining a verified proposal or returning 0.
    access = [(F(1, 2), 0, 0), (F(1, 2), 1, 0)]
    prior = sum(p for p, actor, _ in access if actor == 0)
    agreement = sum(p for p, actor, constructor in access if actor == constructor)
    posterior = sum(p for p, actor, constructor in access if actor == constructor == 0) / agreement
    assert posterior == 1 and posterior > prior

    # Neither observes the other, but both read the same fallible observation.
    shared = [(F(1, 2), 0, 0), (F(1, 2), 1, 1)]
    shared_agreement = sum(p for p, a, c in shared if a == c)
    shared_correct = sum(p for p, a, c in shared if a == c == 0) / shared_agreement
    assert shared_agreement == 1 and shared_correct == F(1, 2)

    # A selector (e.g. initial refusal or residual) admits only the wrong world.
    selected = [(F(1, 2), False, 0, 0), (F(1, 2), True, 1, 1)]
    unconditioned = sum(p for p, _, a, c in selected if a == c == 0) / sum(p for p, _, a, c in selected if a == c)
    conditional = sum(p for p, select, a, c in selected if select and a == c == 0) / sum(
        p for p, select, a, c in selected if select and a == c)
    assert unconditioned == F(1, 2) and conditional == 0

    # Half the episodes pass through with a wrong effect; all repairs are correct.
    pass_wrong, repair_correct = F(1, 2), F(1, 2)
    repair_precision = F(1)
    full_precision = repair_correct / (pass_wrong + repair_correct)
    assert repair_precision == 1 and full_precision == F(1, 2)
    result = {
        "ok": True, "model_calls": 0,
        "access_can_preserve_informative_agreement": {"prior_correct": str(prior), "correct_given_agreement": str(posterior)},
        "sealed_shared_error_can_make_agreement_uninformative": {"agreement": str(shared_agreement), "correct_given_agreement": str(shared_correct)},
        "refusal_validity_residual_selection_must_be_conditioned": {"unconditioned": str(unconditioned), "selected": str(conditional)},
        "line2_pass_through_changes_whole_algorithm": {"repair_precision": str(repair_precision), "whole_precision": str(full_precision)},
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"ok": True, "checks": 4, "out": str(args.out)}))


if __name__ == "__main__":
    main()
