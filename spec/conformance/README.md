# Conformance vectors

Each vector is a directory containing:

```
input.json     headers, method, path, body, trust material
expected.json  { "decision": "DENY", "reasonCode": "AI-3001" }
```

Run: `go test ./test/conformance/...`

Add a vector for every new denial path. Vectors are the contract; the Go
implementation is one client of it.
