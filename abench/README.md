# ABENCH - agent authorisation benchmark

A citable artefact independent of this implementation. Anyone can run it
against any agent-authorisation mechanism.

## Baselines
- A: WSO2 bearer token -> API (the honest "without Agent Authority" case)
- B: API gateway -> API
- C: cloud IAM -> API
- D: MCP authorization -> tool (v0.2)
- P: Agent Authority

## Pre-registered protocol
Fixed hardware, pinned Go, mock upstream at 20 ms, warmed caches,
10 runs x 60 s, first 10 s discarded.

Sweeps: replicas {1,2,4,8} x lease size {1,5,25,100}% x TTL {5,30,120}s
-> the utilisation-latency Pareto frontier.

Blast radius: BR = |actions| x |resources| x exposure_window_seconds.

Publish raw results in `results/` and never edit them after the fact.
