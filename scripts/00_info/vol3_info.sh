#!/usr/bin/env bash
# vol3_info.sh
# Usage: ./vol3_info.sh PATH_TO_MEMORY_IMAGE
# Description: Extracts baseline metadata from a memory image (OS, profile, kdbg offset, etc.)
# Output is stored in outputs/<image>_<timestamp>/00_info/
# Requires: volatility3 in PATH (volatility3 CLI)

set -euo pipefail

IMAGE="$1"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BASENAME=$(basename "$IMAGE")
OUTDIR="outputs/${BASENAME%.*}_${TIMESTAMP}/00_info"

mkdir -p "$OUTDIR"

echo "========================================================"
echo "[INFO SCRIPT] Extracting baseline metadata from memory"
echo "Image: $IMAGE"
echo "Output dir: $OUTDIR"
echo "========================================================"

# List of info-related plugins to execute
PLUGINS=(
  "windows.info"
  "windows.verinfo"
)

# Run the basic info plugins
for plugin in "${PLUGINS[@]}"; do
  outfile="${OUTDIR}/${BASENAME}_${plugin//./_}.txt"
  echo "Running: python3 ./volatility3/vol.py -f \"$IMAGE\" $plugin -> $outfile"
  if python3 ./volatility3/vol.py -f "$IMAGE" $plugin > "$outfile" 2>&1; then
    echo "[OK] $plugin"
  else
    echo "[WARN] $plugin had errors. See $outfile"
  fi
done

# Optional MBR extraction
echo "Running optional MBR extraction..."
MBR_OUT="${OUTDIR}/${BASENAME}_windows_mbr.txt"
if python3 ./volatility3/vol.py -f "$IMAGE" windows.mbr > "$MBR_OUT" 2>&1; then
  echo "[OK] windows.mbr"
else
  echo "[INFO] windows.mbr not supported on this image."
fi

# Extract registry hives and attempt TimeZoneInformation key
echo "Listing loaded registry hives..."
HIVELIST_OUT="${OUTDIR}/${BASENAME}_registry_hivelist.txt"
if python3 ./volatility3/vol.py -f "$IMAGE" windows.registry.hivelist > "$HIVELIST_OUT" 2>&1; then
  echo "[OK] windows.registry.hivelist"
else
  echo "[WARN] windows.registry.hivelist failed."
fi

# Attempt to find timezone key if SYSTEM hive exists
TZ_OUT="${OUTDIR}/${BASENAME}_registry_timezone.txt"
SYSTEM_HIVE=$(grep -i "SYSTEM" "$HIVELIST_OUT" | awk '{print $1}' | head -n 1 || true)
if [[ -n "$SYSTEM_HIVE" ]]; then
  echo "Searching for TimeZoneInformation key in SYSTEM hive..."
  if python3 ./volatility3/vol.py -f "$IMAGE" windows.registry.find_key --hive "$SYSTEM_HIVE" --key "ControlSet001\Control\TimeZoneInformation" > "$TZ_OUT" 2>&1; then
    echo "[OK] windows.registry.find_key (TimeZoneInformation)"
  else
    echo "[WARN] TimeZoneInformation key not found in SYSTEM hive."
  fi
else
  echo "[INFO] SYSTEM hive not found. Skipping timezone extraction."
fi

# Save README summary
README="${OUTDIR}/README_INFO.txt"
echo "Image: $IMAGE" > "$README"
echo "Timestamp: $TIMESTAMP" >> "$README"
echo "Purpose: Baseline metadata extraction (OS, kernel, KDBG, optional MBR, registry hives)" >> "$README"
echo "Plugins executed:" >> "$README"
for plugin in "${PLUGINS[@]}"; do echo "- $plugin" >> "$README"; done
echo "- windows.mbr (optional)" >> "$README"
echo "- windows.registry.hivelist" >> "$README"
echo "- windows.registry.find_key (optional, timezone)" >> "$README"

echo "========================================================"
echo "[DONE] Baseline metadata script complete."
echo "Outputs saved in: $OUTDIR"
echo "========================================================"
