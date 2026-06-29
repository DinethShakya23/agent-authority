# AIP-1/v0.1 - Agent Passport wire specification

Status: FROZEN (build week 7, 2026-08-15)

## 1. Headers

| Header | Required | Description |
|--------|----------|-------------|
| AI-Spec | Yes | Protocol version, must be "AIP-1/v0.1" |
| AI-Passport | Yes | Compact JWS containing the Agent Passport |
| AI-Certificate | Yes | Base64url-encoded DER of agent leaf certificate |
| AI-Chain | No | Comma-separated compact JWSs for delegation chain |
| AI-Execution | Yes | Execution ID |
| AI-Timestamp | Yes | RFC 3339 UTC, millisecond precision |
| AI-Nonce | Yes | Base64url-encoded 128-bit random value |
| AI-Signature | Yes | Base64url-encoded Ed25519 signature over canonical string |

## 2. Canonical string

Length-prefixed (LP), newline-separated, in field order:

```
LP(spec) \n LP(execution_id) \n LP(passport_id) \n LP(method) \n LP(audience) \n LP(path) \n LP(timestamp) \n LP(nonce) \n LP(payload_sha256_hex)
```

Where `LP(s) = decimal_byte_length(s) + ":" + s`

Query parameters in path are sorted by key, then by value.

## 3. Passport JWS

EdDSA (Ed25519) over the passport spec JSON. Header includes `kid` = passportID.

## 4. Verification pipeline

16 normative steps. Steps 1-14 are side-effect free. Step 15 (budget reservation) is the only mutating step.

| Step | Stage | Operation |
|------|-------|-----------|
| 1 | headers | Extract and validate required headers |
| 2 | certificate | Verify certificate chain to trusted root |
| 3 | passport | Parse and verify passport JWS |
| 4 | binding | Verify x5t#S256 thumbprint matches certificate |
| 5 | validity | Check passport validity window |
| 6 | revocation | Check passport is not revoked, verify epoch |
| 7 | timestamp | Verify timestamp within ±30s window |
| 8 | nonce | Verify nonce has not been used before |
| 9 | signature | Reconstruct canonical string and verify Ed25519 signature |
| 10 | audience | Verify audience matches integration |
| 11 | capability | Verify requested capability is granted |
| 12 | schema | Validate request against schema |
| 13 | constraints | Evaluate per-request constraints |
| 14 | delegation | Verify delegation chain monotonicity |
| 15 | budget | Reserve budget (ONLY mutating step) |

## 5. Error codes

Stable AI-xxxx codes. See `pkg/apierr/codes.go` for the authoritative list.
