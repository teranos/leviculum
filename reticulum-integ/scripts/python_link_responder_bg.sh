#!/bin/bash
# Launch python_link_selftest.py --responder detached so the exec step
# returns as soon as the background shell forks. Output goes to
# /tmp/mvr-resp.log for post-hoc inspection. Bug #25 baseline
# measurement companion to `lora_link_python.toml`.
set -e
nohup python3 /opt/integ-scripts/python_link_selftest.py --responder \
  > /tmp/mvr-resp.log 2>&1 < /dev/null &
disown
exit 0
