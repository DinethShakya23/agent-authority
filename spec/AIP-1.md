# AIP-1/v0.1 - Agent Passport wire specification

Status: DRAFT (freeze target: build week 7)

## 1. Headers
AI-Spec, AI-Passport, AI-Certificate, AI-Chain (optional), AI-Execution,
AI-Timestamp, AI-Nonce, AI-Signature.

## 2. Canonical string
Length-prefixed, newline-separated, in order:
spec, execution_id, passport_id, method, audience, path, timestamp, nonce,
payload_sha256_hex.

## 3. Passport JWS
EdDSA over RFC 8785 (JCS) canonical JSON of the passport spec.

## 4. Verification
16 normative steps; steps 1-14 are side-effect free, step 15 (budget
reservation) is the only mutating step.

<!-- Fill from docs/REPORT.md section 9 when freezing. -->
