#!/usr/bin/env bash
# Antlion Passive PCAP Capture & Rotation Controller
# Runs tcpdump with ring-buffer rotation and enforces retention limits.

set -euo pipefail

INTERFACE="${ANTLION_IFACE:-eth0}"
PCAP_DIR="${ANTLION_PCAP_DIR:-/var/log/antlion/pcaps}"
ROTATE_SECONDS="${ANTLION_ROTATE_SECONDS:-300}"
MAX_SIZE_MB="${ANTLION_MAX_SIZE_MB:-50}"
MAX_KEEP_FILES="${ANTLION_MAX_KEEP_FILES:-100}"

mkdir -p "${PCAP_DIR}"

echo "[Antlion Capture] Starting passive capture on interface ${INTERFACE}"
echo "[Antlion Capture] Writing rotating pcaps to ${PCAP_DIR} (Rotate: ${ROTATE_SECONDS}s / ${MAX_SIZE_MB}MB)"

# Background retention cleaner daemon
(
    while true; do
        sleep 60
        # Count existing pcaps and purge oldest if exceeding MAX_KEEP_FILES
        COUNT=$(find "${PCAP_DIR}" -name "capture-*.pcap" | wc -l)
        if [ "${COUNT}" -gt "${MAX_KEEP_FILES}" ]; then
            EXCESS=$((COUNT - MAX_KEEP_FILES))
            echo "[Antlion Retention] Purging ${EXCESS} oldest pcap files to preserve disk"
            find "${PCAP_DIR}" -name "capture-*.pcap" -type f -printf '%T+ %p\n' | sort | head -n "${EXCESS}" | awk '{print $2}' | xargs -r rm -f
        fi
    done
) &
CLEANER_PID=$!

trap 'echo "[Antlion Capture] Terminating capture..."; kill "${CLEANER_PID}" 2>/dev/null || true; exit 0' SIGTERM SIGINT

# Start tcpdump with time (-G) and size (-C) rotation
exec /usr/sbin/tcpdump -i "${INTERFACE}" -nn -s 0 \
    -G "${ROTATE_SECONDS}" \
    -C "${MAX_SIZE_MB}" \
    -w "${PCAP_DIR}/capture-%Y%m%d%H%M%S.pcap" \
    'tcp or udp or icmp'
