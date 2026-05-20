# Architecture Decision Records

One short file per decision: context, decision, consequences.

Write the ADR while you are making the decision, not afterwards. This
directory is also the best interview preparation you will ever produce.

Decisions already made and worth recording:

- 0001 bbolt before etcd
- 0002 Cedar instead of a hand-built policy engine
- 0003 step-ca instead of a hand-built CA
- 0004 pre-deducted leases (stranded budget over overspend)
- 0005 hold, not release, on ambiguous upstream timeout
- 0006 WSO2 verified at issuance only, never on the request path
- 0007 Ed25519 over ECDSA
- 0008 separate Go module for the SDK
