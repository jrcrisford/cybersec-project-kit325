#!/usr/bin/env bash
# run_vol3_scan.sh
# Usage: ./run_vol3_scan.sh PATH TO MEMORY IMAGE
# Description: Runs a set of Volatility3 plugins against a memory image and saves outputs.
# Outputs are saved in a timestamped directory under "outputs/".
# Example: ./run_vol3_scan.sh memory.raw
# Requires: volatility3 in PATH (volatility3 CLI)

### TO BE TESTED - BASIC VERSION

set -euo pipefail

IMAGE="$1"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BASENAME=$(basename "$IMAGE")
OUTDIR="outputs/${BASENAME%.*}_${TIMESTAMP}"

mkdir -p "$OUTDIR"

echo "Image: $IMAGE"
echo "Output dir: $OUTDIR"

# List of Volatility3 plugins to run (Windows-focused) - ADD MORE AS NEEDED
PLUGINS=(
  "windows.pslist"
  "windows.psscan"
  "windows.netscan"
  "windows.cmdline"
  "windows.dlllist"
  "windows.malfind"
  "windows.clipboard"
)

# Run each plugin and capture output and exit status
for plugin in "${PLUGINS[@]}"; do
  outfile="${OUTDIR}/${BASENAME}_${plugin//./_}.txt"
  echo "Running: volatility3 -f \"$IMAGE\" $plugin  -> $outfile"
  if volatility3 -f "$IMAGE" $plugin > "$outfile" 2>&1; then
    echo "[OK] $plugin"
  else
    echo "[WARN] $plugin had errors. See $outfile"
  fi
done

# Save a small summary file
echo "Image: $IMAGE" > "${OUTDIR}/README.txt"
echo "Timestamp: $TIMESTAMP" >> "${OUTDIR}/README.txt"
echo "Plugins run:" >> "${OUTDIR}/README.txt"
for plugin in "${PLUGINS[@]}"; do echo "- $plugin" >> "${OUTDIR}/README.txt"; done

echo "Done. Outputs in $OUTDIR"