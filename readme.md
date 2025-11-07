# KIT325 Memory Forensics Project
## Volatile Memory Analysis & Malware Detection

A comprehensive memory forensics toolkit for the KIT325 Advanced Cybersecurity and eForensics project. Built around the Volatility3 framework, this project focuses on detecting and analyzing malware presence in Windows memory dumps.

## Project Team
- Joshua Crisford
- Aashish Anand
- Emily Tinsley
- Poorvika Kamberkavi

## Project Overview
This project provides automated tools to:
- Extract and analyze volatile artifacts from Windows memory dumps
- Compare clean baseline memory against infected samples
- Document evidence of malware activity and anti-forensic behavior
- Generate structured reports for forensic analysis

## Repository Structure

```
Repository Root/
├── docs/                  # Project documentation
│   └── Stage 1 - SPDA Group Report.docx
│
├── scripts/              # Analysis automation scripts
│   ├── 00_info/         # System information extraction
│   │   ├── vol3_info.sh      # Basic system metadata
│   │   └── vol3_info.md      # Script documentation
│   │
│   ├── 01_scan/         # Process & network analysis
│   │   ├── run_vol3_scan.sh  # Quick system triage
│   │   └── run_vol3_scan.md  # Script documentation
│   │
│   ├── 02_artifacts/    # Comprehensive artifacts
│   │   ├── vol3_artifacts.sh        # Standard extraction
│   │   ├── vol3_artifacts_robust.sh # Corruption-resistant
│   │   └── vol3_artifacts.md        # Plugin documentation
│   │
│   └── 03_comparison/   # Analysis tools
│       ├── vol3_compare.sh   # Clean vs infected comparison
│       └── vol3_compare.md   # Methodology docs
│
├── outputs/             # Analysis results
│   ├── 00_info/        # System information results
│   │   └── {memdump}_{timestamp}/
│   │       ├── windows_info.txt
│   │       └── windows_kdbgscan.txt
│   │
│   ├── 01_scan/        # Process/Network scan results
│   │   └── {memdump}_{timestamp}/
│   │       ├── windows_pslist.txt
│   │       ├── windows_netscan.txt
│   │       └── windows_cmdline.txt
│   │
│   ├── 02_artifacts/   # Comprehensive results
│   │   └── {memdump}_{timestamp}/
│   │       ├── windows_malfind.txt
│   │       ├── windows_callbacks.txt
│   │       └── ... (21+ plugin outputs)
│   │
│   └── 03_comparison/  # Comparison results
│       └── {timestamp}/
│           ├── differences.txt
│           └── analysis_summary.txt
│
└── readme.md           # This documentation
```

Key directories:
- `/scripts`: Automation tools and documentation
- `/outputs`: Generated analysis results
- `/docs`: Project documentation and reports

## Usage Guide

### 1. Basic System Information
Extract core system metadata:
```bash
./scripts/00_info/vol3_info.sh memdump.mem
```
Outputs: System version, kernel info, process list

### 2. Quick Triage
Rapid process and network analysis:
```bash
./scripts/01_scan/run_vol3_scan.sh memdump.mem
```
Outputs: Active processes, network connections, loaded modules

### 3. Comprehensive Analysis
Full artifact extraction (may take longer):
```bash
./scripts/02_artifacts/vol3_artifacts.sh memdump.mem
```
Outputs: Complete forensic dataset across 21+ plugins

### 4. Robust Analysis (Recommended)
Corruption-resistant analysis with fallbacks:
```bash
./scripts/02_artifacts/vol3_artifacts_robust.sh memdump.mem
```
Outputs:
- Standard plugin results where possible
- Corruption analysis reports
- Raw pattern extraction where plugins fail
- Comparison guide for clean vs infected

### 5. Compare Results (once tested with readable image's outputs)
Generate difference reports:
```bash
./scripts/03_comparison/vol3_compare.sh clean.mem infected.mem
```

## Analysis Tips

1. **Clean Baseline**
   - Run full analysis on clean memory first
   - Document normal system behavior
   - Note successful plugin outputs

2. **Infected Analysis**
   - Use robust script for infected dumps
   - Document which plugins fail (forensic evidence)
   - Compare against baseline results

3. **Evidence Collection**
   - Process anomalies
   - Network connections
   - Injected code
   - Plugin failures due to corruption
   - Timeline analysis

## Forensic Methodology

1. **Initial Triage**
   - System information
   - Running processes
   - Network connections

2. **Deep Analysis**
   - Memory structures
   - Code injection
   - Rootkit detection
   - Credential theft

3. **Corruption Analysis**
   - Document plugin failures
   - Raw memory scanning
   - Pattern matching
   - Timeline reconstruction

4. **Comparative Analysis**
   - Process differences
   - Network changes
   - System modifications
   - Anti-forensic indicators

---