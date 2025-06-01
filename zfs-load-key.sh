#!/bin/bash

set -euo pipefail

CONFIG_FILE="/etc/zfs-load-key.conf"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--config /path/to/config.conf]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Use --help for usage."
            exit 1
            ;;
    esac
done

# Read configuration file
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Missing config: $CONFIG_FILE" >&2
    exit 1
fi

# Retrieve key, decrypt it, and load it into ZFS
curl -s ${ZFSKEY_URL} | base64 -d | openssl pkeyutl -decrypt -inkey ${SSL_PRIVATE_KEY} -out ${ZFSKEYFILE} && chmod 600 ${ZFSKEYFILE} && /usr/sbin/zfs load-key -a
