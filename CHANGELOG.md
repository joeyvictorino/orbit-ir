# Changelog

## 0.3.0

- Added unbacked-completion detection: agent claims "done" but independent check failed.
- Added oracle-integrity-violation detection: agent modifies protected test expectations.
- Generator plants both new conditions deterministically alongside existing spoofs.
- Evaluation scores unbacked-completion and oracle-modification recovery separately.
- Report and summary include new finding categories and evaluation rows.
- Expanded test suite from 10 to 12 adversarial tests.
- Inspired by memdoor team-solve: "done is a check, not a claim" and oracle integrity.

## 0.2.0

- Removed the runtime dependency on `ground_truth.json`.
- Limited optional ground truth to post-detection fixture evaluation.
- Added missing transcript and missing control-plane detection.
- Added duplicate message and tool-call identifier detection.
- Added cross-source agent and trace identity checks.
- Added exact source file and line references to findings and trajectories.
- Added schema and timezone-aware timestamp validation.
- Added coordinator ranking with an explicit, configurable evidence threshold.
- Expanded the regression suite from two tests to eight adversarial tests.
- Added a five-version Python CI matrix with SHA-pinned actions.
- Added the technical work-sample PDF to the repository.

## 0.1.0

- Initial synthetic generator and deterministic reconstruction pipeline.
