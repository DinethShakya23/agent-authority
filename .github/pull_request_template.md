## What

## Why

## Invariant checklist
- [ ] No synchronous store/WSO2 call added to the request path (I1)
- [ ] New failure paths fail closed (I2)
- [ ] Budget accounting still pre-deducts (I5)
- [ ] New denial path has a test in `test/adversarial`
- [ ] `spec/` change bumps the version and adds conformance vectors
