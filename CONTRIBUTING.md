# Contributing to ORBIT

Issues and pull requests are welcome, especially new adversarial test cases (evidence that should be flagged and is not, or the reverse).

## Setup

Python 3.10 or newer. There are no runtime dependencies.

```bash
git clone https://github.com/joeyvictorino/orbit-ir
cd orbit-ir
python3 -m unittest discover -s tests -v
pip install ruff==0.17.0 && ruff check .
```

CI runs the same two commands, plus the full synthetic exercise on Python 3.10 to 3.14.

## Ground rules

- Findings must stay deterministic and source-linked: every finding cites the file and line it came from.
- Ground truth may only be used after detections are complete, for evaluation. It must never change a finding. The test `test_analysis_does_not_require_ground_truth` guards this.
- If you change detection logic or the generator, regenerate `artifacts/full_scale/` with `python3 -m orbit_ir.cli demo --workdir work` and copy `work/results/*` there. CI fails if the committed artifacts stop matching (only `runtime_seconds` may differ).
- Add a test for every new detection or validation rule.
- Keep all bundled data synthetic.

## Reporting issues

Include the command you ran, the full error output, and (if possible) the smallest evidence file that reproduces it. Security problems go through [SECURITY.md](SECURITY.md), not a public issue.
