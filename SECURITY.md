# Security Policy

ORBIT is a research and teaching tool that processes synthetic evidence. It makes no network calls, executes no code from its inputs, and has no runtime dependencies beyond the Python standard library.

## Supported versions

Only the latest release (and `main`) receives fixes.

## Reporting a vulnerability

If you find a security problem in ORBIT itself, for example a way that a crafted evidence file makes the analyzer read or write outside the input and output directories, report it privately through GitHub:
<https://github.com/joeyvictorino/orbit-ir/security/advisories/new>

Please do not open a public issue for it. This is a personal open-source project; there is no formal response-time commitment.

## Scope notes

- All bundled data is synthetic. Do not commit real incident data, credentials or personal data to this repository, including in issues and pull requests.
- Analysis results describe record conflicts in the supplied evidence. They are not a statement about the truthfulness of the system that produced the records.
