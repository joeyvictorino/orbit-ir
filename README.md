# ORBIT Agent Incident Reconstruction Lab

A reproducible synthetic work sample for investigating agent coordination, conflicting transcripts, and tool-call evidence at scale.

This project is intentionally explicit about its boundary: it is a synthetic exercise, not a claim of access to a frontier-lab incident. It demonstrates how an investigator can preserve evidence, identify authoritative sources, reconstruct identity-to-effect trajectories, test for transcript/tool-call inconsistencies, rank cross-agent coordinators, and communicate limitations.

## Full-scale exercise

The default generator creates:

- 1,200 agents
- 70,000 message events
- 1,300 transcript records
- 1,300 independent control-plane events
- 700 agents participating in an unsanctioned channel
- 84 deliberately inconsistent transcript/tool-call records

The scale is chosen to make the pipeline exercise realistic review constraints. The scenario and data are original and synthetic.

## Run

No third-party Python packages are required.

```bash
python -m orbit_ir.cli demo --workdir work
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

Results are written to `work/results/`:

- `summary.json`: corpus, findings, evaluation, method, limitations, and runtime
- `findings.csv`: source-linked transcript/tool-call mismatches
- `trajectories.json`: reconstructed identity-to-effect paths
- `evidence_manifest.json`: SHA-256 evidence inventory
- `report.md`: concise decision-grade report

## Evidence model

```text
workload identity -> agent -> tool call -> credential -> resource -> effect -> control decision
```

Transcripts are treated as potentially untrusted. Factual findings require reconciliation to the independent control-plane source using stable identifiers. The pipeline records UTC timestamps, hashes, source references, confidence, and the basis for each trajectory.

## LLM boundary

An LLM is not used for extraction, joins, hashes, mismatch detection, or factual findings. A model can be added after analysis to summarize already-cited records or prioritize analyst review, but generated prose never becomes an evidence source.

## Limitations

- Synthetic evidence is structurally cleaner than production telemetry.
- Stable tool-call identifiers simplify reconciliation.
- Deterministic ground-truth scores validate implementation, not production accuracy.
- Behavior labels do not establish model intent.
- This lab demonstrates forensic mechanics, not model interpretability or RL post-training expertise.

## Author

Joey Victorino

Cyberforensics, incident response, and AI agent security.

## Technical work sample

[Read the four-page technical report](docs/ORBIT_Agent_Incident_Work_Sample.pdf)
