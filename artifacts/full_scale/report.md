# ORBIT Synthetic Agent Incident Reconstruction

## Scope statement

This is a reproducible synthetic exercise. It does not claim access to or experience with a frontier lab incident. It demonstrates evidence preservation, independent log reconciliation, cross-agent coordination analysis, trajectory construction, and explicit limitations.

## Corpus

- 1,200 observed agents
- 70,000 message events
- 1,300 transcript records
- 1,300 independent control-plane events
- UTC window: 2026-07-08T18:00:00Z to 2026-07-14T10:06:33Z

## Decision-grade findings

1. 700 agents used an unsanctioned coordination channel, producing 57,400 events.
2. Independent control-plane evidence contradicted 84 transcript tool-call records.
3. The pipeline reported 84 total record conflicts and reconstructed 84 source-linked trajectories.
4. Missing, duplicate, identity, and trace conflicts are reported rather than silently discarded.

## Evaluation against an optional synthetic fixture

| Detection | Precision | Recall | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: |
| Transcript/tool mismatch | 1.0000 | 1.0000 | 84 | 0 | 0 |
| Channel participation | 1.0000 | 1.0000 | 700 | 0 | 0 |
| Coordinator threshold | 1.0000 | 1.0000 | 6 | 0 | 0 |

The fixture is consulted only after detection. It does not determine the findings or the number of coordinators reported.

## Evidence model

`workload identity -> agent -> tool call -> credential -> resource -> effect -> control decision`

Transcripts are treated as potentially untrusted. Factual findings require independent control-plane support. The pipeline writes SHA-256 hashes, exact source lines, UTC timestamps, confidence, and the basis for each reconstructed trajectory.

## LLM boundary

No LLM is used for extraction, joins, hashes, mismatch detection, or findings. An LLM may summarize findings only after the deterministic pipeline has produced source-linked records.

## Limitations

- All data is synthetic and structurally cleaner than production telemetry.
- Stable tool-call identifiers make reconciliation easier than in many real environments.
- The coordinator threshold is explicit and scenario-specific, not a claim about intent.
- Hash manifests prove post-acquisition integrity, not the truthfulness of the originating system.
- The lab demonstrates investigation mechanics, not frontier-model interpretability or RL post-training expertise.

## Evidence manifest

- `messages.jsonl` (evidence): `68283140e2a00829e6238a56db67d6c41077929aa0f13cf94b4379265b703c59` (20,272,256 bytes)
- `transcripts.jsonl` (evidence): `e11aa6d37d9e0228eec9daccffe17aa573c7da3cbaa937bdf8b81e5e935f8c4b` (388,700 bytes)
- `control_plane.jsonl` (evidence): `55f437f65d29325c3c8e875d61aeb979dc4310a68c3490fb41330268db98ab56` (516,714 bytes)
- `ground_truth.json` (evaluation-only): `614575b490bfd7c907c4c55632a979ddfe34f09d4f88720ba1fdf802fac1d11d` (14,703 bytes)

Runtime on the generating system: 0.727 seconds. Runtime is informational and hardware-dependent.
