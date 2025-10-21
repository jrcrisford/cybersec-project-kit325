#!/usr/bin/env bash
# vol3_info.sh
# Usage: ./vol3_info.sh PATH_TO_MEMORY_IMAGE
# Description: Extracts baseline metadata from a memory image (OS, profile, kdbg offset, timezone, etc.)
# Output is expected to be stored in outputs/<image>_<timestamp>/00_info/
# Requires: volatility3 in PATH

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
  "windows.kdbgscan"
  "windows.verinfo"
)

# Run the simple plugins first
for plugin in "${PLUGINS[@]}"; do
  outfile="${OUTDIR}/${BASENAME}_${plugin//./_}.txt"
  echo "Running: volatility3 -f \"$IMAGE\" $plugin -> $outfile"
  if volatility3 -f "$IMAGE" $plugin > "$outfile" 2>&1; then
    echo "[OK] $plugin"
  else
    echo "[WARN] $plugin had errors. See $outfile"
  fi
done

# Handle optional plugins (MBR may not exist on all images)
echo "Running optional MBR extraction (if available)..."
MBR_OUT="${OUTDIR}/${BASENAME}_windows_mbr.txt"
if volatility3 -f "$IMAGE" windows.mbr > "$MBR_OUT" 2>&1; then
  echo "[OK] windows.mbr"
else
  echo "[INFO] windows.mbr not supported on this image."
fi

# Registry timezone extraction
echo "Extracting timezone registry information..."
TZ_OUT="${OUTDIR}/${BASENAME}_registry_timezone.txt"
if volatility3 -f "$IMAGE" windows.printkey --key "ControlSet001\\Control\\TimeZoneInformation" > "$TZ_OUT" 2>&1; then
  echo "[OK] windows.printkey (Timezone)"
else
  echo "[WARN] windows.printkey timezone key not found."
fi

# Save README summary for this script
README="${OUTDIR}/README_INFO.txt"
echo "Image: $IMAGE" > "$README"
echo "Timestamp: $TIMESTAMP" >> "$README"
echo "Purpose: Baseline metadata extraction (OS, kernel, timezone, KDBG)" >> "$README"
echo "Plugins executed:" >> "$README"
for plugin in "${PLUGINS[@]}"; do echo "- $plugin" >> "$README"; done
echo "- windows.mbr (optional)" >> "$README"
echo "- windows.printkey (timezone)" >> "$README"

echo "========================================================"
echo "[DONE] Baseline metadata script complete."
echo "Outputs saved in: $OUTDIR"
echo "========================================================"