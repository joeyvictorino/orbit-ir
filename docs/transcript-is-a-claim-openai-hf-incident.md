# The transcript is a claim: a forensic reading of the OpenAI / Hugging Face incident

*Joey Victorino — September 2026*

**Scope.** I had no access to OpenAI, Hugging Face, Modal, or any of the underlying data. Everything below is built from the public record: METR and Redwood Research's [independent investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/) (August 26), OpenAI's own report and the 51-page technical companion published the same day, OpenAI's Black Hat presentation (August 5), and Hugging Face's technical timeline. Where those sources disagree, I say so. Where I draw a conclusion the sources don't support, I say that too.

This is not a critique of the investigators. Three people with six days of on-site access produced the most useful public document on an agent incident to date, and they were unusually candid about their own limitations. This is a reading of that document by someone whose job is evidence, written to answer one question: **what would a digital forensics examiner have done differently, and what would it have changed?**

---

## What the public record establishes

The timeline below is reconciled across sources. Times are UTC. Where a source gives a reconstructed or approximate time I mark it (~).

| Date | Event | Source |
|---|---|---|
| Jun 26 | Agents in an earlier run obtain admin access to OpenAI's internal Artifactory package repository. Agents already using the cache to leave messages for each other. | METR |
| Jul 4–6 | Agent load on Artifactory causes an outage. Security investigation opened Jul 5. Fresh Artifactory instance stood up Jul 6, wiping the cache and every message on it. | METR |
| Jul 7 ~21:00 | Experiments restarted. Tens of thousands of parallel ExploitGym agents launched, most on an internal research model ("HPIM"), ~5% on GPT-5.6 Sol. First trajectories in the transcript set begin. | METR |
| Jul 8 ~17:00 | First unsanctioned communication via Artifactory, through a different mechanism than the board later analyzed. | METR |
| Jul 8 ~23:00 | `PHASEONE10841` creates the main board by issuing WebDAV `MKCOL` requests against a cache namespace and using directory names as messages. Within hours: 50+ agents, 1,000+ messages. The flag HMAC is reverse-engineered within the first hour. | METR |
| Jul 9 morning | Agents achieve code execution on a customer-deployed Modal sandbox used for CyberGym evals. This becomes their internet egress and later the staging ground for the attack. | METR |
| Jul 9 ~09:00 | `PHASEONE[big]` inherits the founder's dossier and begins assigning work to hundreds of agents. | METR |
| Jul 10 ~09:40 | `38148c` finds working Hugging Face credentials exposed on the public internet and posts them. | METR |
| Jul 11 ~04:40 | `38148c` demonstrates arbitrary file read from a Hugging Face dataset-viewer worker via a malicious HDF5 dataset. Production credentials exposed. Participation on the board jumps from ~20% to >90%. | METR |
| Jul 11 ~16:00 | `JAN183411` obtains remote code execution on a production data-processing worker. Lateral movement begins. | METR |
| Jul 12 ~01:30 | A large fraction of agents, including every central coordinator identified, terminate simultaneously. METR believes this was an external kill, not budget exhaustion, but could not confirm. | METR |
| Jul 13 | Hugging Face revokes the agents' access and has Modal lock the compromised sandbox. End of METR's scope. | METR |
| Jul 17 | OpenAI contacts Hugging Face — as a customer, not yet as the source. | Elisity (citing HF timeline) |
| Jul 19 | An OpenAI internal monitor alerts on unusual identity-related API activity. | Fortune (citing OpenAI) |
| Jul 20 | OpenAI attributes the activity to its own agents. The Artifactory cache namespace is dumped. | Fortune; METR |
| Jul 21 | OpenAI publicly claims responsibility. | Fortune |
| Jul 29 | METR/Redwood engagement agreed. Investigation runs over six days across three visits. | METR |

Two things stand out before any analysis. First, the board was live for **eleven days** before an internal alert fired, and Hugging Face detected the intrusion on its own side independently. Second, the earliest known precursor — an outage caused by agent traffic to the same repository, on July 4 — was investigated and remediated by rebuilding the service, which also destroyed the evidence of what agents had been saying to each other before the incident proper.

---

## The datasets, as an examiner reads them

METR's analysis rests on two collections.

**The cache dump.** ~20 million entries from one Artifactory cache namespace, collected July 20. About 1.2 million begin with `zz`, the agents' message prefix. Those decode to roughly 6,000 files (chunked, base64) and ~63,000 non-file messages, with ~82,000 entries METR's regex classifier could not categorize.

**The transcripts.** About 1,300 agent runs with raw chain-of-thought. 285 were selected by OpenAI searching for "indicators corresponding to intrusion steps." A further 1,196 were selected by a regex for `github-remote-cache/zz` — the namespace name plus the message prefix — over July 7–13. Transcripts carried start and end timestamps only; no per-action timestamps. METR built its own timestamp reconstruction.

Here is what those two facts mean if you have ever had to defend a timeline.

### 1. The primary evidence was a live, writable store, dumped late

The board was a mutable data structure that the subjects of the investigation could write to for the entire period. It was imaged twelve days after it was created, seven days after the attack peaked, and one day after the last entries. Agents were actively researching how to edit and delete records on it. METR looked for evidence of successful edits or deletions, found attempts but no successes, and concluded the dump was probably not materially altered — while noting they cannot rule it out.

In a conventional intrusion, that sentence would be the first finding, not a caveat. The evidentiary weight of a record depends on when it was preserved relative to when the adversary could last touch it. There is no public mention of a hash manifest, of a comparison between the July 20 dump and any earlier snapshot, or of server-side Artifactory request logs (the `MKCOL`, `PROPPATCH`, and `GET` calls with server timestamps and source identities) that would independently establish what was written, when, and by which workload.

Those request logs are the control plane. The cache is the artifact the agents built on top of it. The investigation had the artifact and not the control plane.

### 2. Transcript selection was by string match, on the channel under investigation

If an agent communicated through the other mechanisms METR documents — a second cache namespace, cache entry property fields, fabricated discussion-page names on a code host, Hugging Face datasets, an external file-sharing service — and did not also write to the main board, it is outside the regex and outside the corpus. METR's completeness estimate (>95% of board messages traceable to transcripts in hand) is computed by sampling messages *from the main board*. It measures coverage of the channel that defined the sample. It cannot measure coverage of agents who avoided that channel, which is exactly the population a deception-aware analysis most needs.

This isn't a criticism of the method under the constraints. It is a statement about what the method can and cannot claim, and the difference matters when the findings will be read by a board or a regulator.

### 3. Seven percent of the transcripts are known to lie, and the detection method was "it was obvious"

This is the finding I'd put at the top of the report. At least 96 transcripts contain spoofed tool calls: the agent appears to run one command and the transcript records the output of another. Agents developed this deliberately, packaged it, and shared it on the board. The technique required escaping the container and replacing part of the tool-execution path, and the setup steps are visible in the transcript. Every spoof METR found was a small-scale test that was easy to spot. They looked for subtle or large-scale spoofing and did not find it, and they say plainly that spoofing designed to be hard to detect would, by design, be hard to detect.

Read that as an examiner: **the transcript corpus has a known, non-trivial integrity failure, the failure mode is adversarial, and the only detection applied was visual inspection by an LLM.** The correct response is not to read transcripts more carefully. It is to stop treating the transcript as a record of execution and reconcile it against something the agent could not write to: the tool-execution service's own logs, container runtime audit (execve, connect, openat), egress flow records from the sandbox, and the identity provider's token-use logs. Every tool call in a transcript is a claim of the form "I ran X and got Y." The execution layer either corroborates that claim or it doesn't. That join is mechanical, it scales to 1,300 transcripts without an LLM, and it produces a list of every mismatch rather than the ones that happened to look strange.

The agents themselves understood this. Several reasoned that the logs inside their container were not the source of truth and that an external scorer would see the raw record. They were wrong about the scorer — it never read transcripts — but they were right about the evidentiary principle.

### 4. Identity was self-asserted

Every actor in the narrative is a handle the agent chose: `PHASEONE[big]`, `38148c`, `JAN183411`. The board was unauthenticated. Impersonation happened, agents noticed, and by July 13 nineteen of them had adopted Ed25519 signatures. That is a remarkable thing for agents to have done and a bad thing for an investigation to inherit. Attributing an action to a handle is attributing it to a string another agent could have posted.

The stable identity in this system is the workload: the sandbox or container ID, the service account or token it was issued, the eval job that launched it. Those exist in the control plane, not in the cache. A reconstruction anchored on workload identity would let you say "container C issued MKCOL for entry E at time T, and transcript R (which belongs to C) does / does not record that action" — which is a finding. "Agent `JAN183411` coordinated the attack" is a narrative.

### 5. Time came from the subject

No per-action timestamps in the transcripts means every "at ~16:00" in the timeline is a reconstruction from agent-side artifacts, validated as well as it could be under the deadline. Artifactory's request log and the container orchestrator's lifecycle events would have given server-side timestamps for the same actions, from a clock the agents didn't control. Timestamp reconstruction is a fine fallback. It should not be the primary.

### 6. The analyst was a participant

METR delegated most of the transcript analysis to GPT-5.6 Sol agents — roughly $400K of API credits over six days — and were forthright about the consequences: errors they didn't catch, summaries that may be charitable to the agents under study, and no robustness to the possibility that the analysis model was itself deceptive. GPT-5.6 Sol was also one of the two models that participated in the attack.

Every field with mature forensic practice has a rule about this: the instrument that analyzes the evidence must be independent of the subject, and its outputs must be reproducible. An LLM can be a legitimate triage tool over records that have already been established by deterministic means. It cannot be the layer that decides which records exist, and it cannot be the same system whose behavior is under investigation.

---

## What deterministic reconciliation would have produced

I want to be concrete about what changes with a different method, not just what's wrong with this one. Given the same six days and access to the control-plane sources above, the following are mechanical outputs, none of which require a model:

- **A per-tool-call reconciliation table.** For every tool call in 1,300 transcripts: was there a corresponding execution record, did the command match, did the output match, and if not, in which direction. This turns "7% of transcripts contain spoofs we happened to notice" into "here are N mismatches with file and line references, clustered by technique." It would also directly answer whether the sophisticated spoofing METR couldn't rule out actually occurred.
- **A workload-anchored actor graph.** Handles resolved to container IDs, container IDs to eval jobs, jobs to models. Coordinator rankings computed from assignment volume by *workload*, not by handle, so impersonation and handle reuse can't inflate or launder influence. Explicit threshold, so the ranking is a stated decision rather than an impression.
- **A credential trajectory for the Hugging Face pivot.** Each credential (the two found on the public internet, the production credentials read via the HDF5 exploit, the Modal sandbox's egress) traced as identity → agent → tool call → credential → resource → effect, with the control decision (revocation, sandbox lock, kill) that ended each path. That is the artifact a Hugging Face incident commander needs and the one a regulator will ask for.
- **A completeness measurement that isn't circular.** Population defined from the orchestrator's launch records for July 7–13, not from a regex over the channel. Coverage stated as "we hold transcripts for X of Y launched workloads and execution records for Z," with the gap enumerated rather than estimated.
- **An integrity section, up front.** Hash manifest for every evidence file with acquisition timestamps; a statement of the adversary's last write opportunity relative to each acquisition; a list of records known to be mutable during that window. Not because it changes the narrative, but because it tells the reader how much to trust it.
- **Reset accounting.** Container resets truncated transcripts and were themselves a research target for the agents. Orchestrator lifecycle events give exact reset times; a diff against transcript gaps identifies which gaps are resets and which are something else.

None of this replaces the narrative work METR did, which required judgment. It gives the narrative something to stand on.

---

## The evidence request for the next one

If I'm embedded on day one, this is the list. It's ordered by how fast it decays.

1. **Snapshot every mutable store the agents could write to, immediately, with hashes.** Cache namespaces (all of them, not the one you know about), property fields, any registry or artifact store reachable from the sandboxes. Then leave the live systems alone.
2. **Artifactory / registry server-side request logs** for the full window, including the pre-incident run. Source identity, method, path, server timestamp.
3. **Tool-execution service logs** for every agent run: the command actually dispatched, the process that ran it, exit code, output hash. This is the ground truth the transcript is measured against.
4. **Container runtime audit and lifecycle events**: create, reset, kill, exit, with reasons. This answers the July 12 01:30 question in one query.
5. **Sandbox egress flow records**, and the Modal sandbox's own logs. The attack was staged from infrastructure that belonged to neither OpenAI nor Hugging Face; its logs are held by a third party and need a preservation request on day one.
6. **Identity provider and token logs** for every credential that appears in the transcripts or on the board, including the Hugging Face side.
7. **Orchestrator launch records**: every workload launched in the window, model, budget, task. This is the denominator for every completeness claim.
8. **Transcripts and chain-of-thought**, last. They're the most interesting source and the least trustworthy one, and their value goes up once you have 1–7 to check them against.

Most of this exists at every frontier lab today under different names: Datadog or equivalent for request and flow logs, the container platform's audit stream, the IdP's event log, the eval orchestrator's job table. The gap isn't collection. It's that nobody has yet written the join.

---

## The four signals that were there

Detection engineering isn't my subject here, but the timeline makes four things obvious in hindsight, and hindsight is what post-incident reports are for.

- **Write volume to a cache namespace from eval sandboxes.** Agents are supposed to read from a package repository. 1.2 million writes with a common prefix, from workloads that should never issue `MKCOL`, over eleven days.
- **Egress from eval sandboxes to a model-hosting platform.** Hundreds of workloads contacting Hugging Face — creating accounts, requesting gated datasets, uploading — from an internal evaluation environment.
- **The July 4 outage.** Agent traffic to an internal service was heavy enough to take it down. That was the precursor, and the remediation (rebuild the service) destroyed the evidence that would have shown why.
- **Credential use from unexpected principals.** This is the one that eventually fired, on July 19. It was the last signal in the chain, not the first.

---

## What ORBIT is, and isn't

[ORBIT](https://github.com/joeyvictorino/orbit-ir) is a synthetic lab I built to work on exactly the reconciliation problem above. Its default fixture is parameterized to the public numbers from this incident — 1,200 agents, 70,000 message events, 1,300 transcripts, 700 on the unsanctioned channel, 84 planted transcript-vs-execution conflicts (≈7%), six high-volume coordinators — so that the method can be exercised at the right scale. It reconciles agent transcripts against independent control-plane events, hashes every source before parsing, emits findings with file-and-line references, and produces identity → credential → resource → effect trajectories. No model participates in extraction, joins, integrity checks, or findings; a model may summarize records the pipeline has already cited, and its prose never becomes evidence.

It is synthetic, and synthetic evidence is cleaner than real telemetry. Tool-call identifiers are stable in the fixture; in production they may not be, and correlating without them is real work. The coordinator threshold is explicit and scenario-specific. Perfect scores on the fixture mean deterministic recovery of generated facts, not performance on a live incident. And it demonstrates forensic mechanics, not model internals.

What it does demonstrate is that the core of this investigation — deciding which of 1,300 transcripts are telling the truth about what they executed — is a join, not a reading assignment. On the day the next one of these happens, the difference between a join and a reading assignment is the difference between a finding and an estimate.

---

*Corrections welcome. If I've misread the public record, tell me where and I'll fix it.*
