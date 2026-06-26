#!/usr/bin/env bash
set -euo pipefail
# Requires tla2tools.jar on the classpath.
java -cp "${TLA_TOOLS:-tla2tools.jar}" tlc2.TLC -workers auto -config budget.cfg budget.tla
