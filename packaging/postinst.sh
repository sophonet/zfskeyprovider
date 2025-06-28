#!/bin/bash
set -e

# Reload systemd and enable service only if systemctl is available
if command -v systemctl >/dev/null 2>&1; then
    # Reload systemd to pick up the new service
    systemctl daemon-reload

    # Optional: enable service so it starts on boot
    systemctl enable zfskeyprovider.service

    echo "✅ zfskeyprovider has been installed."
    echo "👉 Edit /etc/zfskeyprovider.toml before starting the service:"
    echo "   sudo nano /etc/zfskeyprovider.toml"
    echo "Then start the service with:"
    echo "   sudo systemctl start zfskeyprovider"
    echo "👉 On ZFS system, edit zfs-load-cryptkey.conf before enabling service:"
    echo "   sudo nano /etc/zfs-load-cryptkey.conf"
    echo "   sudo systemctl enable zfs-load-key.service"
else
    echo "systemctl not found. Please configure and start zfskeyprovider manually."
fi
