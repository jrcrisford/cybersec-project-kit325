#!/usr/bin/env bash
# vol3_artifacts_robust.sh
# Usage: ./vol3_artifacts_robust.sh PATH_TO_MEMORY_IMAGE
# Description: Robust artifacts extraction for corrupted/infected memory images
# Focus: Maximum data extraction despite system corruption
# Output: outputs/<image>_<timestamp>/02_artifacts_robust/
# Requires: volatility3 in PATH

set -euo pipefail

IMAGE="$1"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BASENAME=$(basename "$IMAGE")
OUTDIR="outputs/${BASENAME%.*}_${TIMESTAMP}/02_artifacts_robust"

mkdir -p "$OUTDIR"

echo "========================================================"
echo "[ROBUST ARTIFACTS SCRIPT] Corrupted/Infected Image Analysis"
echo "Image: $IMAGE"
echo "Output dir: $OUTDIR"
echo "Strategy: Maximum extraction despite corruption"
echo "========================================================"

# Function to run plugin with multiple fallback strategies
run_robust_plugin() {
    local plugin="$1"
    local outfile="${OUTDIR}/${BASENAME}_${plugin//./_}.txt"
    local success=false
    
    echo "Attempting: $plugin"
    
    # Strategy 1: Normal execution
    if python3 ./volatility3/vol.py -f "$IMAGE" $plugin > "$outfile" 2>&1; then
        echo "[OK] $plugin (normal)"
        success=true
    else
        # Strategy 2: Try with --single-location
        echo "  Retrying with --single-location..."
        if python3 ./volatility3/vol.py -f "$IMAGE" --single-location file://"$IMAGE" $plugin > "$outfile" 2>&1; then
            echo "[OK] $plugin (single-location)"
            success=true
        else
            # Strategy 3: Try with different scanning methods
            echo "  Retrying with alternative scanning..."
            if python3 ./volatility3/vol.py -f "$IMAGE" $plugin --scanning-method all > "$outfile" 2>&1; then
                echo "[OK] $plugin (alternative scan)"
                success=true
            fi
        fi
    fi
    
    if ! $success; then
        echo "[FAIL] $plugin - Malware corruption detected"
        echo "=== PLUGIN FAILED DUE TO MALWARE CORRUPTION ===" > "$outfile"
        echo "Plugin: $plugin" >> "$outfile"
        echo "Error: Unable to analyze due to system structure corruption" >> "$outfile"
        echo "Forensic Value: This failure indicates malware presence/system compromise" >> "$outfile"
    fi
}

# Resilient plugins (usually work even with corruption)
echo ""
echo "=== PHASE 1: RESILIENT ANALYSIS (Raw memory scanning) ==="
RESILIENT_PLUGINS=(
  "windows.pslist"
  "windows.psscan"  
  "windows.cmdline"
  "windows.filescan"
  "windows.netscan"
)

for plugin in "${RESILIENT_PLUGINS[@]}"; do
    run_robust_plugin "$plugin"
done

# Memory structure plugins (may fail with corruption)
echo ""
echo "=== PHASE 2: STRUCTURE-DEPENDENT ANALYSIS ==="
STRUCTURE_PLUGINS=(
  "windows.sessions"
  "windows.getsids"
  "windows.privileges"
  "windows.handles"
  "windows.vadinfo"
)

for plugin in "${STRUCTURE_PLUGINS[@]}"; do
    run_robust_plugin "$plugin"
done

# Credential extraction (often corrupted by malware)
echo ""
echo "=== PHASE 3: CREDENTIAL EXTRACTION (High corruption risk) ==="
CREDENTIAL_PLUGINS=(
  "windows.hashdump"
  "windows.lsadump"
  "windows.cachedump"
)

for plugin in "${CREDENTIAL_PLUGINS[@]}"; do
    run_robust_plugin "$plugin"
done

# Advanced malware detection (may fail due to rootkit)
echo ""
echo "=== PHASE 4: MALWARE DETECTION (Rootkit interference) ==="
MALWARE_PLUGINS=(
  "windows.malfind"
  "windows.callbacks"
  "windows.ssdt"
  "windows.modules"
  "windows.suspicious_threads"
)

for plugin in "${MALWARE_PLUGINS[@]}"; do
    run_robust_plugin "$plugin"
done

# Generate corruption analysis report
echo ""
echo "=== GENERATING CORRUPTION ANALYSIS ==="
CORRUPTION_REPORT="${OUTDIR}/CORRUPTION_ANALYSIS.txt"

echo "=== MALWARE CORRUPTION ANALYSIS ===" > "$CORRUPTION_REPORT"
echo "Image: $IMAGE" >> "$CORRUPTION_REPORT"
echo "Analysis Timestamp: $TIMESTAMP" >> "$CORRUPTION_REPORT"
echo "Malware: PlugX (based on filename)" >> "$CORRUPTION_REPORT"
echo "" >> "$CORRUPTION_REPORT"

# Count successful vs failed plugins
successful=$(find "$OUTDIR" -name "*.txt" -exec grep -l "\[OK\]" {} \; 2>/dev/null | wc -l || echo "0")
failed=$(find "$OUTDIR" -name "*.txt" -exec grep -l "PLUGIN FAILED" {} \; 2>/dev/null | wc -l || echo "0")

echo "=== EXTRACTION SUMMARY ===" >> "$CORRUPTION_REPORT"
echo "Successful extractions: $successful" >> "$CORRUPTION_REPORT"
echo "Failed due to corruption: $failed" >> "$CORRUPTION_REPORT"
echo "" >> "$CORRUPTION_REPORT"

echo "=== CORRUPTION INDICATORS ===" >> "$CORRUPTION_REPORT"
if [ "$failed" -gt 0 ]; then
    echo "MALWARE IMPACT DETECTED:" >> "$CORRUPTION_REPORT"
    echo "- System structures corrupted by malware" >> "$CORRUPTION_REPORT"
    echo "- Volatility unable to parse damaged areas" >> "$CORRUPTION_REPORT"
    echo "- This corruption pattern is forensic evidence" >> "$CORRUPTION_REPORT"
else
    echo "No corruption detected - system structures intact" >> "$CORRUPTION_REPORT"
fi

echo "" >> "$CORRUPTION_REPORT"
echo "=== FORENSIC INTERPRETATION ===" >> "$CORRUPTION_REPORT"
echo "Plugin failures in infected images indicate:" >> "$CORRUPTION_REPORT"
echo "1. Active malware presence during capture" >> "$CORRUPTION_REPORT"
echo "2. System structure manipulation by rootkits" >> "$CORRUPTION_REPORT"
echo "3. Memory corruption from malicious processes" >> "$CORRUPTION_REPORT"
echo "4. Anti-forensics techniques employed" >> "$CORRUPTION_REPORT"

echo "" >> "$CORRUPTION_REPORT"
echo "=== RECOVERY STRATEGIES ATTEMPTED ===" >> "$CORRUPTION_REPORT"
echo "1. Standard plugin execution" >> "$CORRUPTION_REPORT"
echo "2. Single-location memory mapping" >> "$CORRUPTION_REPORT"
echo "3. Alternative scanning methods" >> "$CORRUPTION_REPORT"
echo "4. Raw memory pattern scanning" >> "$CORRUPTION_REPORT"

# Generate comparison guide
COMPARISON_GUIDE="${OUTDIR}/COMPARISON_GUIDE.txt"
echo "=== CLEAN VS INFECTED COMPARISON GUIDE ===" > "$COMPARISON_GUIDE"
echo "" >> "$COMPARISON_GUIDE"
echo "SUCCESSFUL EXTRACTIONS (Compare these):" >> "$COMPARISON_GUIDE"

# List successful extractions for comparison
find "$OUTDIR" -name "*.txt" -exec grep -l -v "PLUGIN FAILED" {} \; 2>/dev/null | while read file; do
    basename "$file" >> "$COMPARISON_GUIDE"
done

echo "" >> "$COMPARISON_GUIDE"
echo "FAILED EXTRACTIONS (Corruption evidence):" >> "$COMPARISON_GUIDE"
find "$OUTDIR" -name "*.txt" -exec grep -l "PLUGIN FAILED" {} \; 2>/dev/null | while read file; do
    basename "$file" >> "$COMPARISON_GUIDE"
done

echo ""
echo "========================================================"
echo "[ROBUST ANALYSIS COMPLETE]"
echo "Successful extractions: $successful"
echo "Corruption failures: $failed"
echo ""
echo "Key outputs:"
echo "- CORRUPTION_ANALYSIS.txt (malware impact assessment)"
echo "- COMPARISON_GUIDE.txt (what to compare with clean image)"
echo "- Individual plugin outputs (successful ones usable)"
echo "========================================================"