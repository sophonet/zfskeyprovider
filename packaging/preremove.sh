#!/bin/bash
set -e

# Stop and disable the service if it is running
if systemctl is-enabled --quiet zfskeyprovider.service; then
    systemctl disable zfskeyprovider.service || true
fi

if systemctl is-active --quiet zfskeyprovider.service; then
    systemctl stop zfskeyprovider.service || true
fi

echo "🛑 zfskeyprovider has been stopped and disabled."
