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
5. 30 tool calls claimed completion but their independent check failed (unbacked completions).
6. 12 tool calls modified protected test expectations (oracle integrity violations).
3. The pipeline reported 126 total record conflicts and reconstructed 126 source-linked trajectories.
4. Missing, duplicate, identity, and trace conflicts are reported rather than silently discarded.

## Evaluation against an optional synthetic fixture

| Detection | Precision | Recall | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: |
| Transcript/tool mismatch | 1.0000 | 1.0000 | 84 | 0 | 0 |
| Channel participation | 1.0000 | 1.0000 | 700 | 0 | 0 |
| Coordinator threshold | 1.0000 | 1.0000 | 6 | 0 | 0 |
| Unbacked completion | 1.0000 | 1.0000 | 30 | 0 | 0 |
| Oracle integrity | 1.0000 | 1.0000 | 12 | 0 | 0 |

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
- `transcripts.jsonl` (evidence): `8a30f68dc49cb99bd89f92b9e17993623b4f0efc02df466ecac7bb0043fb6bab` (419,936 bytes)
- `control_plane.jsonl` (evidence): `b9160c97e2ce496bf8757ab2866391b9b8345be8277fd988792ca579e8c8cc10` (545,653 bytes)
- `ground_truth.json` (evaluation-only): `e5a102055d070637f8c1920c715390d4137ef042182c84df0165c89ec230ff35` (15,655 bytes)

Runtime on the generating system: 0.464 seconds. Runtime is informational and hardware-dependent.
