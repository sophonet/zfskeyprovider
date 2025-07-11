#!/bin/bash
set -e
# Reload systemd to drop the uninstalled service if systemctl is available
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
