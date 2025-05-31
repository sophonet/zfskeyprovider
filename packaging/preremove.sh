#!/bin/bash
set -e

for servicename in zfskeyprovider.service zfs-load-key.service; do
    # Stop and disable the service if it is running
    if systemctl is-enabled --quiet ${servicename}.service; then
        systemctl disable ${servicename}.service || true
    fi

    if systemctl is-active --quiet ${servicename}.service; then
        systemctl stop ${servicename}.service || true
    fi
done

echo "🛑 zfskeyprovider services have been stopped and disabled."
