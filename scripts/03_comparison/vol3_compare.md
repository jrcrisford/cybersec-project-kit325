# Memory Image Comparison Script - Before/After Malware Analysis

## Overview
vol3_compare.sh implements Stretch Objective 7 for the KIT325 Memory Forensics project by automating a before/after comparison of memory snapshots taken pre- and post-simulated malware injection. The script runs a focused set of Volatility3 plugins against both images, extracts core artefacts (process lists, network connections, kernel modules, handles, and command lines), and produces sorted diffs and a consolidated MALWARE_COMPARISON_REPORT.txt summarising new or changed artefacts. Due to validation issues with the infected snapshot (plugin translation/symbol requirements), the script could not be fully executed in this evaluation. With a readable post-infection image or minor adjustments (for example, adding --single-location for .mem files or supplying appropriate symbol files), vol3_compare.sh provides a forensically sound workflow for identifying injection-introduced processes, suspicious connections, and newly loaded modules — outcomes routinely used in SOC/CSIRT incident triage and attribution.

## Project Objective Alignment
### **Stretch Objective 7**: Compare multiple memory snapshots
- Captures memory before and after an "incident"
- Compares differences to identify malware artifacts
- Demonstrates temporal analysis capabilities

## Script Purpose
This script automates the comparison of two memory images to identify:
1. **New Processes** - Malware execution and persistence
2. **New Network Connections** - C&C communications and data exfiltration
3. **New Kernel Modules** - Rootkit installation and system modification
4. **Changed System State** - Overall impact assessment

## Usage
```bash
./vol3_compare.sh CLEAN_IMAGE INFECTED_IMAGE
```

### Example Workflow
```bash
# 1. Capture baseline (clean) memory
./capture_memory.sh > clean_memory.raw

# 2. Execute malware simulation (EICAR or benign sample)
./simulate_malware.sh

# 3. Capture post-incident memory
./capture_memory.sh > infected_memory.raw

# 4. Compare images
./vol3_compare.sh clean_memory.raw infected_memory.raw
```

## Analysis Methodology

### Phase 1: Baseline Analysis
- Analyzes clean memory image with core plugins
- Establishes normal system state
- Documents legitimate processes, connections, and modules

### Phase 2: Post-Incident Analysis  
- Analyzes infected memory image with same plugins
- Captures post-malware system state
- Identifies all active artifacts

### Phase 3: Differential Analysis
- Compares outputs using `comm` and `diff` utilities
- Identifies new/changed artifacts
- Generates detailed comparison report

## Output Structure
```
outputs/comparison_<timestamp>/
├── clean/                          # Baseline analysis
│   ├── clean_windows_pslist.txt
│   ├── clean_windows_netscan.txt
│   ├── clean_windows_modules.txt
│   └── clean_windows_handles.txt
├── infected/                       # Post-incident analysis
│   ├── infected_windows_pslist.txt
│   ├── infected_windows_netscan.txt
│   ├── infected_windows_modules.txt
│   └── infected_windows_handles.txt
├── differences/                    # Differential analysis
│   ├── new_processes.txt
│   ├── new_connections.txt
│   ├── new_modules.txt
│   └── comparison_summary.txt
└── MALWARE_COMPARISON_REPORT.txt   # Project deliverable
```

## Key Comparison Areas

### 1. Process Analysis
**What it detects:**
- New malware processes
- Process injection targets  
- Persistence mechanism processes
- Command line changes

**Example findings:**
```
New Processes in Infected Image:
- malware.exe (PID 1234)
- cmd.exe (suspicious parent)
- powershell.exe (base64 encoded)
```

### 2. Network Activity
**What it detects:**
- C&C server connections
- Data exfiltration channels
- Backdoor listeners
- Network scanning activity

**Example findings:**
```
New Network Connections:
- TCP 192.168.1.100:443 -> 185.243.115.84:8080
- UDP 0.0.0.0:53 -> 8.8.8.8:53 (DNS tunneling)
```

### 3. Kernel Module Changes
**What it detects:**
- Rootkit installation
- Driver modifications
- System file replacement
- Kernel hook installation

**Example findings:**
```
New Kernel Modules:
- suspicious_driver.sys
- modified_ntoskrnl.exe
```

## Project Deliverables

### 1. **MALWARE_COMPARISON_REPORT.txt**
Comprehensive analysis report including:
- Executive summary of changes
- Technical details of new artifacts
- Timeline of malware injection
- IOC (Indicators of Compromise) list

### 2. **Evidence Package**
Complete set of before/after artifacts for:
- Forensic report documentation
- Class presentation materials
- Peer review and validation

## Real-World Applications

### SOC Use Cases:
- **Incident Response**: Comparing pre/post-compromise states
- **Threat Hunting**: Identifying persistence mechanisms
- **Malware Analysis**: Understanding malware behavior

### CSIRT Applications:
- **Timeline Reconstruction**: Determining attack progression
- **Impact Assessment**: Measuring compromise extent
- **Attribution**: Correlating with known threat actors

## Advanced Analysis Features

### Automated Differencing
- Uses Unix `comm` utility for precise comparison
- Filters out noise and formatting differences
- Focuses on meaningful security changes

### Timeline Correlation
- Correlates process creation with network connections
- Maps file access patterns to malware behavior
- Builds comprehensive attack timeline

## Integration with Project Workflow

### Step 1: Baseline Capture
```bash
# Capture clean system state
./vol3_info.sh clean_memory.raw       # System baseline
./vol3_artifacts.sh clean_memory.raw  # User activity baseline
```

### Step 2: Incident Simulation
```bash
# Execute EICAR test file or benign malware sample
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
./eicar.com
```

### Step 3: Post-Incident Analysis
```bash
# Capture infected system state
./vol3_artifacts.sh infected_memory.raw
./vol3_compare.sh clean_memory.raw infected_memory.raw
```

### Step 4: Report Generation
Use comparison outputs to populate:
- **Project forensic report**
- **Class presentation slides**
- **Memory artifact cheat sheet**

This script demonstrates advanced memory forensics capabilities essential for modern cybersecurity professionals and with some modifications (post-testing with two readable images) provides concrete evidence for project assessment.