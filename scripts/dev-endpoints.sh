#!/usr/bin/env bash

# Stable local endpoint defaults. Keep long-running integration listeners
# separate from disposable smoke-test listeners so sessions and restarts do
# not silently move an enrolled agent to a different port.
SIEM_DEV_PLATFORM_FALLBACK_URL="http://127.0.0.1:5081"
SIEM_DEV_PERSISTENT_PLATFORM_URL="https://127.0.0.1:5443"
SIEM_DEV_API_SMOKE_URL="http://127.0.0.1:5080"
SIEM_DEV_WEB_SMOKE_URL="http://127.0.0.1:5081"
SIEM_DEV_WINDOWS_LAB_BIND_URL="http://0.0.0.0:4444"
SIEM_DEV_WINDOWS_LAB_LOCAL_URL="http://127.0.0.1:4444"
