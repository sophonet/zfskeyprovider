#!/bin/bash

set -euo pipefail

CONFIG_FILE="/etc/zfs-load-cryptkey.conf"

# Override with env variable if set
if [[ -n "${ZFSLOADCRYPTKEY_CONFIG:-}" ]]; then
    CONFIG_FILE="$ZFSLOADCRYPTKEY_CONFIG"
fi

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
    # Only abort if required variables are not set
    if [[ -z "${ZFSKEY_URL:-}" || -z "${SSL_PRIVATE_KEY:-}" || -z "${ZFSKEYFILE:-}" ]]; then
        echo "Missing config: $CONFIG_FILE and required environment variables (ZFSKEY_URL, SSL_PRIVATE_KEY, ZFSKEYFILE) are not set." >&2
        exit 1
    fi
fi

# Retrieve key, decrypt it, and load it into ZFS
curl -s ${ZFSKEY_URL} | base64 -d | openssl pkeyutl -decrypt -inkey ${SSL_PRIVATE_KEY} -out ${ZFSKEYFILE} && chmod 600 ${ZFSKEYFILE} && /usr/sbin/zfs load-key -a
