# ORBIT Synthetic Agent Incident Reconstruction

## Scope statement

This is a reproducible synthetic exercise. It does not claim access to or experience with a frontier lab incident. It demonstrates evidence preservation, independent log reconciliation, cross-agent coordination analysis, trajectory construction, and explicit limitations.

## Corpus

- 40 observed agents
- 500 message events
- 80 transcript records
- 80 independent control-plane events
- UTC window: 2026-07-08T18:00:00Z to 2026-07-09T09:30:17.120000Z

## Decision-grade findings

1. 24 agents used an unsanctioned coordination channel, producing 410 events.
2. Independent control-plane evidence contradicted 7 transcript tool-call records.
3. The pipeline reported 7 total record conflicts and reconstructed 7 source-linked trajectories.
4. Missing, duplicate, identity, and trace conflicts are reported rather than silently discarded.

## Evaluation against an optional synthetic fixture

| Detection | Precision | Recall | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: |
| Transcript/tool mismatch | 1.0000 | 1.0000 | 7 | 0 | 0 |
| Channel participation | 1.0000 | 1.0000 | 24 | 0 | 0 |
| Coordinator threshold | 1.0000 | 1.0000 | 3 | 0 | 0 |

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

- `messages.jsonl` (evidence): `92bd18ef6cba67ea2bd095be1ff637183a5e25406b68d068efae7c3c7b7f13af` (144,800 bytes)
- `transcripts.jsonl` (evidence): `e12b6c6ff8205d19fed26be0776283f574b3038f42aa99a39c4a6777508504ea` (23,920 bytes)
- `control_plane.jsonl` (evidence): `69312b21fbd1b99ca44927284f2c2f6a6213999d4d6277884d38b21ee8278401` (31,842 bytes)
- `ground_truth.json` (evaluation-only): `b307aaab3c908db934048bfcd331010491f66e640c4a1cd1b5a0e8c0cce383ad` (1,004 bytes)

Runtime on the generating system: 0.012 seconds. Runtime is informational and hardware-dependent.
