#!/usr/bin/env bash
# vol3_compare.sh
# Usage: ./vol3_compare.sh CLEAN_IMAGE INFECTED_IMAGE
# Description: (FOR MORE DETAILS, REFER TO DOCUMENTATION FOR THIS SCRIPT) Compares clean vs infected memory images for malware analysis
# Project Focus: Before/after incident comparison (Stretch Objective 7)
# Output: outputs/comparison_<timestamp>/
# Requires: volatility3 in PATH

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 CLEAN_IMAGE INFECTED_IMAGE"
    echo "Example: $0 clean_memory.raw infected_memory.raw"
    exit 1
fi

CLEAN_IMAGE="$1"
INFECTED_IMAGE="$2"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
OUTDIR="outputs/comparison_${TIMESTAMP}"

mkdir -p "$OUTDIR"/{clean,infected,differences}

echo "========================================================"
echo "[COMPARISON SCRIPT] Clean vs Infected Memory Analysis"
echo "Clean Image: $CLEAN_IMAGE"
echo "Infected Image: $INFECTED_IMAGE"
echo "Output dir: $OUTDIR"
echo "Project Goal: Stretch Objective 7 - Compare snapshots"
echo "========================================================"

# Core plugins for comparison analysis
COMPARISON_PLUGINS=(
  "windows.pslist"
  "windows.netscan"
  "windows.modules"
  "windows.handles"
  "windows.cmdline"
)

# Analyze clean image
echo ""
echo "=== ANALYZING CLEAN (BASELINE) IMAGE ==="
for plugin in "${COMPARISON_PLUGINS[@]}"; do
  clean_out="${OUTDIR}/clean/clean_${plugin//./_}.txt"
  echo "Running: python3 ./volatility3/vol.py -f \"$CLEAN_IMAGE\" $plugin"
  if python3 ./volatility3/vol.py -f "$CLEAN_IMAGE" $plugin > "$clean_out" 2>&1; then
    echo "[OK] Clean: $plugin"
  else
    echo "[WARN] Clean: $plugin had errors"
  fi
done

# Analyze infected image
echo ""
echo "=== ANALYZING INFECTED (POST-INCIDENT) IMAGE ==="
for plugin in "${COMPARISON_PLUGINS[@]}"; do
  infected_out="${OUTDIR}/infected/infected_${plugin//./_}.txt"
  echo "Running: python3 ./volatility3/vol.py -f \"$INFECTED_IMAGE\" $plugin"
  if python3 ./volatility3/vol.py -f "$INFECTED_IMAGE" $plugin > "$infected_out" 2>&1; then
    echo "[OK] Infected: $plugin"
  else
    echo "[WARN] Infected: $plugin had errors"
  fi
done

# Generate comparison report
echo ""
echo "=== GENERATING COMPARISON ANALYSIS ==="
COMPARISON_REPORT="${OUTDIR}/MALWARE_COMPARISON_REPORT.txt"

echo "=== MEMORY FORENSICS COMPARISON ANALYSIS ===" > "$COMPARISON_REPORT"
echo "Project: KIT325 Memory Forensics - Stretch Objective 7" >> "$COMPARISON_REPORT"
echo "Analysis Type: Before/After Malware Injection Comparison" >> "$COMPARISON_REPORT"
echo "Clean Image: $CLEAN_IMAGE" >> "$COMPARISON_REPORT"
echo "Infected Image: $INFECTED_IMAGE" >> "$COMPARISON_REPORT"
echo "Analysis Date: $TIMESTAMP" >> "$COMPARISON_REPORT"
echo "" >> "$COMPARISON_REPORT"

# Process comparison
echo "=== PROCESS ANALYSIS COMPARISON ===" >> "$COMPARISON_REPORT"
if [ -f "${OUTDIR}/clean/clean_windows_pslist.txt" ] && [ -f "${OUTDIR}/infected/infected_windows_pslist.txt" ]; then
    echo "--- New Processes in Infected Image ---" >> "$COMPARISON_REPORT"
    # Extract process names and compare
    grep -v "Volatility" "${OUTDIR}/clean/clean_windows_pslist.txt" | awk '{print $2}' | sort > "${OUTDIR}/differences/clean_processes.tmp" 2>/dev/null || touch "${OUTDIR}/differences/clean_processes.tmp"
    grep -v "Volatility" "${OUTDIR}/infected/infected_windows_pslist.txt" | awk '{print $2}' | sort > "${OUTDIR}/differences/infected_processes.tmp" 2>/dev/null || touch "${OUTDIR}/differences/infected_processes.tmp"
    
    comm -13 "${OUTDIR}/differences/clean_processes.tmp" "${OUTDIR}/differences/infected_processes.tmp" > "${OUTDIR}/differences/new_processes.txt" 2>/dev/null || echo "No new processes detected" > "${OUTDIR}/differences/new_processes.txt"
    
    if [ -s "${OUTDIR}/differences/new_processes.txt" ]; then
        cat "${OUTDIR}/differences/new_processes.txt" >> "$COMPARISON_REPORT"
    else
        echo "No new processes detected" >> "$COMPARISON_REPORT"
    fi
else
    echo "Process comparison failed - check input files" >> "$COMPARISON_REPORT"
fi

echo "" >> "$COMPARISON_REPORT"

# Network comparison
echo "=== NETWORK CONNECTIONS COMPARISON ===" >> "$COMPARISON_REPORT"
if [ -f "${OUTDIR}/clean/clean_windows_netscan.txt" ] && [ -f "${OUTDIR}/infected/infected_windows_netscan.txt" ]; then
    echo "--- New Network Connections in Infected Image ---" >> "$COMPARISON_REPORT"
    # Extract IPs and ports
    grep -E "TCP|UDP" "${OUTDIR}/clean/clean_windows_netscan.txt" | awk '{print $3}' | sort > "${OUTDIR}/differences/clean_connections.tmp" 2>/dev/null || touch "${OUTDIR}/differences/clean_connections.tmp"
    grep -E "TCP|UDP" "${OUTDIR}/infected/infected_windows_netscan.txt" | awk '{print $3}' | sort > "${OUTDIR}/differences/infected_connections.tmp" 2>/dev/null || touch "${OUTDIR}/differences/infected_connections.tmp"
    
    comm -13 "${OUTDIR}/differences/clean_connections.tmp" "${OUTDIR}/differences/infected_connections.tmp" > "${OUTDIR}/differences/new_connections.txt" 2>/dev/null || echo "No new connections detected" > "${OUTDIR}/differences/new_connections.txt"
    
    if [ -s "${OUTDIR}/differences/new_connections.txt" ]; then
        cat "${OUTDIR}/differences/new_connections.txt" >> "$COMPARISON_REPORT"
    else
        echo "No new network connections detected" >> "$COMPARISON_REPORT"
    fi
else
    echo "Network comparison failed - check input files" >> "$COMPARISON_REPORT"
fi

echo "" >> "$COMPARISON_REPORT"

# Module comparison
echo "=== KERNEL MODULES COMPARISON ===" >> "$COMPARISON_REPORT"
if [ -f "${OUTDIR}/clean/clean_windows_modules.txt" ] && [ -f "${OUTDIR}/infected/infected_windows_modules.txt" ]; then
    echo "--- New Modules in Infected Image ---" >> "$COMPARISON_REPORT"
    grep -v "Volatility" "${OUTDIR}/clean/clean_windows_modules.txt" | awk '{print $2}' | sort > "${OUTDIR}/differences/clean_modules.tmp" 2>/dev/null || touch "${OUTDIR}/differences/clean_modules.tmp"
    grep -v "Volatility" "${OUTDIR}/infected/infected_windows_modules.txt" | awk '{print $2}' | sort > "${OUTDIR}/differences/infected_modules.tmp" 2>/dev/null || touch "${OUTDIR}/differences/infected_modules.tmp"
    
    comm -13 "${OUTDIR}/differences/clean_modules.tmp" "${OUTDIR}/differences/infected_modules.tmp" > "${OUTDIR}/differences/new_modules.txt" 2>/dev/null || echo "No new modules detected" > "${OUTDIR}/differences/new_modules.txt"
    
    if [ -s "${OUTDIR}/differences/new_modules.txt" ]; then
        cat "${OUTDIR}/differences/new_modules.txt" >> "$COMPARISON_REPORT"
    else
        echo "No new kernel modules detected" >> "$COMPARISON_REPORT"
    fi
else
    echo "Module comparison failed - check input files" >> "$COMPARISON_REPORT"
fi

# Generate investigation summary for project report
echo "" >> "$COMPARISON_REPORT"
echo "=== INVESTIGATION SUMMARY FOR PROJECT REPORT ===" >> "$COMPARISON_REPORT"
echo "1. MALWARE INJECTION EVIDENCE:" >> "$COMPARISON_REPORT"
echo "   - Check 'differences/new_processes.txt' for malware processes" >> "$COMPARISON_REPORT"
echo "   - Review 'differences/new_connections.txt' for C&C communications" >> "$COMPARISON_REPORT"
echo "   - Analyze 'differences/new_modules.txt' for rootkit modules" >> "$COMPARISON_REPORT"
echo "" >> "$COMPARISON_REPORT"
echo "2. TIMELINE CORRELATION:" >> "$COMPARISON_REPORT"
echo "   - Clean baseline captured before malware injection" >> "$COMPARISON_REPORT"
echo "   - Infected state shows post-injection artifacts" >> "$COMPARISON_REPORT"
echo "   - Differences highlight malware persistence mechanisms" >> "$COMPARISON_REPORT"
echo "" >> "$COMPARISON_REPORT"
echo "3. SOC/CSIRT IMPLICATIONS:" >> "$COMPARISON_REPORT"
echo "   - Demonstrates memory-based threat detection capabilities" >> "$COMPARISON_REPORT"
echo "   - Shows value of volatile artifact analysis in incident response" >> "$COMPARISON_REPORT"
echo "   - Provides evidence for threat attribution and IOC development" >> "$COMPARISON_REPORT"

# Clean up temporary files
rm -f "${OUTDIR}/differences/"*.tmp 2>/dev/null || true

echo ""
echo "========================================================"
echo "[COMPARISON ANALYSIS COMPLETE]"
echo "Key Outputs:"
echo "- Clean baseline: ${OUTDIR}/clean/"
echo "- Infected state: ${OUTDIR}/infected/"
echo "- Differences: ${OUTDIR}/differences/"
echo "- Report: ${OUTDIR}/MALWARE_COMPARISON_REPORT.txt"
echo ""
echo "=== PROJECT DELIVERABLE READY ==="
echo "Use MALWARE_COMPARISON_REPORT.txt for:"
echo "1. Forensic report evidence section"
echo "2. Class presentation findings"
echo "3. Demonstration of before/after analysis"
echo "========================================================"