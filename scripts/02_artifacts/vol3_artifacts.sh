#!/usr/bin/env bash
# vol3_artifacts.sh
# Usage: ./vol3_artifacts.sh PATH_TO_MEMORY_IMAGE
# Description: Extracts volatile artifacts and user activity for project analysis
# Focus: User sessions, credentials, persistence, timeline artifacts
# Output: outputs/<image>_<timestamp>/02_artifacts/
# Requires: volatility3 in PATH

set -euo pipefail

IMAGE="$1"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BASENAME=$(basename "$IMAGE")
OUTDIR="outputs/${BASENAME%.*}_${TIMESTAMP}/02_artifacts"

mkdir -p "$OUTDIR"

echo "========================================================"
echo "[ARTIFACTS SCRIPT] Volatile Artifacts & User Activity"
echo "Image: $IMAGE"
echo "Output dir: $OUTDIR"
echo "Project Focus: Memory forensics for incident response"
echo "========================================================"

# User Activity & Session Analysis (Project Objective 4.iii)
echo "=== EXTRACTING USER SESSIONS & ACTIVITY ==="
USER_PLUGINS=(
  "windows.sessions"
  "windows.getservicesids"
  "windows.getsids"
  "windows.privileges"
)

for plugin in "${USER_PLUGINS[@]}"; do
  outfile="${OUTDIR}/${BASENAME}_${plugin//./_}.txt"
  echo "Running: python3 ./volatility3/vol.py -f \"$IMAGE\" $plugin -> $outfile"
  if python3 ./volatility3/vol.py -f "$IMAGE" $plugin > "$outfile" 2>&1; then
    echo "[OK] $plugin"
  else
    echo "[WARN] $plugin had errors. See $outfile"
  fi
done

# Credential & Sensitive Data Recovery (Project Objective 5.iii)
echo ""
echo "=== EXTRACTING CREDENTIALS & SENSITIVE DATA ==="
CREDENTIAL_PLUGINS=(
  "windows.hashdump"
  "windows.lsadump"
  "windows.cachedump"
)

for plugin in "${CREDENTIAL_PLUGINS[@]}"; do
  outfile="${OUTDIR}/${BASENAME}_${plugin//./_}.txt"
  echo "Running: python3 ./volatility3/vol.py -f \"$IMAGE\" $plugin -> $outfile"
  if python3 ./volatility3/vol.py -f "$IMAGE" $plugin > "$outfile" 2>&1; then
    echo "[OK] $plugin"
  else
    echo "[WARN] $plugin had errors. See $outfile"
  fi
done

# Malware & Persistence Artifacts (Project Objective 4.v, 5.ii)
echo ""
echo "=== DETECTING MALWARE & PERSISTENCE ARTIFACTS ==="
MALWARE_PLUGINS=(
  "windows.callbacks"
  "windows.ssdt"
  "windows.modules"
  "windows.modscan"
  "windows.suspicious_threads"
  "windows.skeleton_key_check"
)

for plugin in "${MALWARE_PLUGINS[@]}"; do
  outfile="${OUTDIR}/${BASENAME}_${plugin//./_}.txt"
  echo "Running: python3 ./volatility3/vol.py -f \"$IMAGE\" $plugin -> $outfile"
  if python3 ./volatility3/vol.py -f "$IMAGE" $plugin > "$outfile" 2>&1; then
    echo "[OK] $plugin"
  else
    echo "[WARN] $plugin had errors. See $outfile"
  fi
done

# File System & Timeline Artifacts (Project Objective 5)
echo ""
echo "=== EXTRACTING FILESYSTEM & TIMELINE ARTIFACTS ==="
TIMELINE_PLUGINS=(
  "windows.filescan"
  "windows.handles"
  "windows.vadinfo"
  "windows.mftscan.MFTScan"
)

for plugin in "${TIMELINE_PLUGINS[@]}"; do
  outfile="${OUTDIR}/${BASENAME}_${plugin//./_}.txt"
  echo "Running: python3 ./volatility3/vol.py -f \"$IMAGE\" $plugin -> $outfile"
  if python3 ./volatility3/vol.py -f "$IMAGE" $plugin > "$outfile" 2>&1; then
    echo "[OK] $plugin"
  else
    echo "[WARN] $plugin had errors. See $outfile"
  fi
done

# Advanced Analysis for SOC/CSIRT workflows
echo ""
echo "=== ADVANCED INCIDENT RESPONSE ANALYSIS ==="
ADVANCED_PLUGINS=(
  "windows.thrdscan"
  "windows.mutantscan"
  "windows.symlinkscan"
  "windows.unloadedmodules"
)

for plugin in "${ADVANCED_PLUGINS[@]}"; do
  outfile="${OUTDIR}/${BASENAME}_${plugin//./_}.txt"
  echo "Running: python3 ./volatility3/vol.py -f \"$IMAGE\" $plugin -> $outfile"
  if python3 ./volatility3/vol.py -f "$IMAGE" $plugin > "$outfile" 2>&1; then
    echo "[OK] $plugin"
  else
    echo "[WARN] $plugin had errors. See $outfile"
  fi
done

# Generate Timeline Summary (Project Objective 5)
echo ""
echo "=== GENERATING TIMELINE SUMMARY ==="
TIMELINE_OUT="${OUTDIR}/${BASENAME}_timeline_summary.txt"
echo "Creating timeline summary from artifacts..."
echo "=== MEMORY FORENSICS TIMELINE SUMMARY ===" > "$TIMELINE_OUT"
echo "Image: $IMAGE" >> "$TIMELINE_OUT"
echo "Analysis Timestamp: $TIMESTAMP" >> "$TIMELINE_OUT"
echo "Generated for: KIT325 Memory Forensics Project" >> "$TIMELINE_OUT"
echo "" >> "$TIMELINE_OUT"

# Extract key timestamps and events
echo "=== KEY SYSTEM EVENTS ===" >> "$TIMELINE_OUT"
if [ -f "${OUTDIR}/${BASENAME}_windows_sessions.txt" ]; then
  echo "--- User Sessions ---" >> "$TIMELINE_OUT"
  grep -E "(Session|Login|Logoff)" "${OUTDIR}/${BASENAME}_windows_sessions.txt" 2>/dev/null | head -10 >> "$TIMELINE_OUT" || echo "No session data found" >> "$TIMELINE_OUT"
fi

if [ -f "${OUTDIR}/${BASENAME}_windows_handles.txt" ]; then
  echo "--- Recent File Handles ---" >> "$TIMELINE_OUT"
  grep -E "\.(exe|dll|bat|ps1|cmd|tmp)" "${OUTDIR}/${BASENAME}_windows_handles.txt" 2>/dev/null | head -15 >> "$TIMELINE_OUT" || echo "No file handles found" >> "$TIMELINE_OUT"
fi

# Project-specific summary
PROJECT_SUMMARY="${OUTDIR}/PROJECT_ANALYSIS_SUMMARY.txt"
echo "=== KIT325 MEMORY FORENSICS PROJECT SUMMARY ===" > "$PROJECT_SUMMARY"
echo "Student/Group: Aashish Anand/Group #09" >> "$PROJECT_SUMMARY"
echo "Analysis Date: $TIMESTAMP" >> "$PROJECT_SUMMARY"
echo "Memory Image: $IMAGE" >> "$PROJECT_SUMMARY"
echo "" >> "$PROJECT_SUMMARY"
echo "=== PROJECT OBJECTIVES ADDRESSED ===" >> "$PROJECT_SUMMARY"
echo "Objective 4.iii: User sessions and logged-in users extracted" >> "$PROJECT_SUMMARY"
echo "Objective 4.iv: Credential remnants and sensitive data recovered" >> "$PROJECT_SUMMARY"
echo "Objective 4.v: Persistence and malware artifacts identified" >> "$PROJECT_SUMMARY"
echo "Objective 5: System timeline and activity narrative created" >> "$PROJECT_SUMMARY"
echo "" >> "$PROJECT_SUMMARY"
echo "=== FORENSIC FINDINGS FOR REPORT ===" >> "$PROJECT_SUMMARY"
echo "1. User Activity Analysis:" >> "$PROJECT_SUMMARY"
echo "   - Check windows_sessions.txt for active/terminated sessions" >> "$PROJECT_SUMMARY"
echo "   - Review windows_privileges.txt for privilege escalation" >> "$PROJECT_SUMMARY"
echo "" >> "$PROJECT_SUMMARY"
echo "2. Credential Security Assessment:" >> "$PROJECT_SUMMARY"
echo "   - Password hashes extracted (hashdump.txt)" >> "$PROJECT_SUMMARY"
echo "   - LSA secrets analyzed (lsadump.txt)" >> "$PROJECT_SUMMARY"
echo "   - Cached credentials reviewed (cachedump.txt)" >> "$PROJECT_SUMMARY"
echo "" >> "$PROJECT_SUMMARY"
echo "3. Malware & Persistence Indicators:" >> "$PROJECT_SUMMARY"
echo "   - System call hooks checked (ssdt.txt)" >> "$PROJECT_SUMMARY"
echo "   - Suspicious threads identified (suspicious_threads.txt)" >> "$PROJECT_SUMMARY"
echo "   - Module integrity verified (modules.txt, modscan.txt)" >> "$PROJECT_SUMMARY"
echo "" >> "$PROJECT_SUMMARY"
echo "4. File System Activity:" >> "$PROJECT_SUMMARY"
echo "   - Recent file access patterns (filescan.txt)" >> "$PROJECT_SUMMARY"
echo "   - Open file handles (handles.txt)" >> "$PROJECT_SUMMARY"
echo "   - Memory mapped files (vadinfo.txt)" >> "$PROJECT_SUMMARY"

echo ""
echo "========================================================"
echo "[PROJECT ANALYSIS COMPLETE]"
echo "Outputs saved in: $OUTDIR"
echo ""