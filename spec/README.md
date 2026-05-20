# AIP-1 - Agent Passport wire specification

Implementation-neutral. Anything that speaks AIP-1 interoperates with any
conformant firewall, regardless of language or vendor.

- `AIP-1.md`          normative specification
- `conformance/`      test vectors + a runner any implementation can use
- `schemas/`          JSON Schema for passports, receipts, resource payloads

Versioning: the spec version is independent of the software version. A change
to the canonical string, header set, or passport payload is a breaking change
and requires a new version plus new vectors.

This directory is a citable research artefact. Keep it self-contained.
