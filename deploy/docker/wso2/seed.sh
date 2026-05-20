#!/usr/bin/env bash
# Provision WSO2 for the demo. No manual console clicks - one-command
# reproducibility is the point of v0.1.
#
#   1. create the agent identity (Agent ID + Secret)
#   2. create and assign the Procurement-Specialist role
#   3. register the agent-integrator application, enable the agent flow,
#      enable CIBA, authorise the required scopes
#   4. write AGENT_ID / AGENT_SECRET to ../../../.env
set -euo pipefail
echo "TODO: implement against the WSO2 SCIM2 and application management APIs"
