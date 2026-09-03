# W2/W3 Final Validation - 2026-08-05

This record supersedes stale runtime numbers in the earlier W2/W3 notes. It records the
post-Docker-migration verification of the current workspace.

## Code checks

- `python -m pytest -q`: 87 passed.
- `python -m compileall -q src tests scripts`: passed.
- `ruff check src tests scripts`: passed.
- `docker compose config --quiet`: passed.
- API `/healthz`: HTTP 200.

## Docker rebuild

- Docker Desktop WSL data root: `D:\DockerDesktop\wsl`.
- Compose registry prefix is configurable with `CONTAINER_REGISTRY_PREFIX`; the local
  default is `docker.m.daocloud.io` because direct Docker Hub access was unavailable.
- API image: `threat-report-agent-api`, about 590 MB.
- Ghidra Worker image: `threat-report-agent-ghidra-worker`, about 2.59 GB.
- Ghidra release: 12.1.2, archive SHA-256
  `b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d`.
- Running services: API, PostgreSQL/pgvector, MinIO, Temporal, control Worker,
  intake Worker, parser Worker, script Worker, document Worker and Ghidra Worker.
- BuildKit cache after cleanup: 0 B. Project images and volumes were retained.

## Real container acceptance

Sample: Windows `notepad.exe`, SHA-256
`db1131b5060bcfad80fc21d7bd333d9a7de3eee5190c5586d0a3a096fd563b87`.

Task `c7fd264b-9c4d-4316-a97c-538e58495bd4` completed with:

- Task lifecycle `SUCCEEDED`; analysis outcome `PARTIAL` only because no primary model
  credentials were configured and deterministic report wording was used.
- `python-zipfile-safe-reader`, `pe-parser`, and `ghidra-headless` ToolRuns all `SUCCEEDED`.
- 1 Artifact, 19,183 Evidence records, 14 Candidate Claims, and a generated report revision.
- 3,644 audit events; `/audit/integrity` returned `valid: true` with a terminal HMAC-SHA256 seal.
- The Ghidra raw output remained an object-store reference; PostgreSQL retained summary and
  provenance metadata rather than the large payload.

## Review boundary

The fixed-point review snapshot is `.data/review-w2w3-clean` at commit `5e417aa`, reviewed
against parent `31c7752`. The W2/W3 deterministic extraction and isolated Temporal path are
accepted for first-phase work. The following remain explicitly deferred hardening or later
phase work and are not claimed complete here: production Model Gateway calls and restricted
model payload retention, independent Audit Sealer/WORM deployment, adversarial consensus
execution for high-value claims, per-ToolRun object-store grants, and analysis-package
import/replay.
## Directory archive regression

- `expand_directory` now shares the bounded ZIP recursion used by direct ZIP submission.
  Nested members retain `logical_path` and `parent_path` links such as
  `folder/outer.zip!/inner.zip!/payload.bin`.
- File count, expanded byte size, archive depth, unsafe paths and encrypted-entry gates apply
  equally to directory-contained archives.
- Temporal directory analysis performs a bounded read-only preflight, then delegates each archive to
  the isolated intake Worker, preventing duplicate local/Worker expansion while preserving the
  same manifest and gate semantics.
- Regression coverage includes nested directory archives, depth limits and encrypted ZIP gates.
  Targeted intake and directory-chain tests passed; the full suite is 87 passed.