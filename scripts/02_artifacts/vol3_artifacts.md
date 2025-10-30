# Volatile Artifacts Analysis Script - KIT325 Project Focus

## Overview
`vol3_artifacts.sh` is specifically designed to address the **core project objectives** outlined in our Memory Forensics project. This script focuses on extracting volatile artifacts that are essential for incident response, malware investigation, and SOC/CSIRT workflows.

## Project Alignment
This script directly addresses the following **Project Objectives**:

### **Objective 4.iii**: Logged-in users and user sessions
- `windows.sessions` - Active user sessions and login times
- `windows.getsids` - User SIDs and account information  
- `windows.getservicesids` - Service account mappings

### **Objective 4.iv**: Command history and sensitive data
- `windows.hashdump` - Password hashes from SAM registry
- `windows.lsadump` - LSA secrets and cached passwords
- `windows.cachedump` - Domain cached credentials

### **Objective 4.v**: Persistence and malware artifacts
- `windows.callbacks` - System callback modifications (rootkits)
- `windows.ssdt` - System Service Descriptor Table hooks
- `windows.suspicious_threads` - Anomalous thread behavior
- `windows.modules` - Loaded kernel modules analysis
- `windows.modscan` - Hidden/unlinked module detection
- `windows.skeleton_key_check` - Active Directory attack detection

### **Objective 5**: Timeline and narrative building
- `windows.filescan` - File objects and recent access patterns
- `windows.handles` - Open file handles and resource usage
- `windows.vadinfo` - Virtual memory mapping analysis
- `windows.mftscan.MFTScan` - Master File Table analysis for timeline reconstruction

### **Advanced SOC/CSIRT Analysis**: Extended capabilities
- `windows.thrdscan` - Thread scanning for code injection detection
- `windows.mutantscan` - Mutex objects for malware synchronization analysis
- `windows.symlinkscan` - Symbolic links for persistence mechanism detection
- `windows.unloadedmodules` - Previously loaded modules for evasion analysis

## Script Structure

### Phase 1: User Activity Analysis
Extracts user sessions, privileges, and account information to understand who was active on the system and what privileges they had.

### Phase 2: Credential Recovery
Safely extracts password hashes and cached credentials that could indicate credential theft or lateral movement attempts.

### Phase 3: Malware Detection
Analyzes system-level hooks, callbacks, and suspicious threads that indicate rootkit or advanced malware presence.

### Phase 4: Timeline Creation
Builds a comprehensive view of file system activity and memory-mapped resources for timeline correlation.

### Phase 5: Advanced Analysis
Performs specialized incident response analysis including:
- Thread scanning for injection detection
- Mutex analysis for malware synchronization
- Symbolic link analysis for persistence mechanisms
- Unloaded module detection for evasion techniques

### Phase 6: Project Deliverables
Automatically generates:
- **PROJECT_ANALYSIS_SUMMARY.txt** - Summary for forensic report (includes student/group identification)
- **timeline_summary.txt** - Key events and timestamps extracted from artifacts

## Output Structure
```
outputs/<image>_<timestamp>/02_artifacts/
├── User Activity/
│   ├── windows_sessions.txt
│   ├── windows_getsids.txt
│   ├── windows_getservicesids.txt
│   └── windows_privileges.txt
├── Credentials/
│   ├── windows_hashdump.txt
│   ├── windows_lsadump.txt
│   └── windows_cachedump.txt
├── Malware Detection/
│   ├── windows_callbacks.txt
│   ├── windows_ssdt.txt
│   ├── windows_modules.txt
│   ├── windows_modscan.txt
│   ├── windows_suspicious_threads.txt
│   └── windows_skeleton_key_check.txt
├── Timeline Artifacts/
│   ├── windows_filescan.txt
│   ├── windows_handles.txt
│   ├── windows_vadinfo.txt
│   └── windows_mftscan_MFTScan.txt
├── Advanced Analysis/
│   ├── windows_thrdscan.txt
│   ├── windows_mutantscan.txt
│   ├── windows_symlinkscan.txt
│   └── windows_unloadedmodules.txt
└── Project Deliverables/
    ├── PROJECT_ANALYSIS_SUMMARY.txt
    └── <image>_timeline_summary.txt
```

## Key Artifacts for Project Report

### 1. **User Activity Evidence**
- **Who**: Active user sessions and account SIDs
- **When**: Login/logout timestamps and session duration
- **Privileges**: Elevated permissions and privilege escalation

### 2. **Credential Security Assessment**
- **Password Security**: Hash strength and cracking potential
- **Lateral Movement**: Cached domain credentials
- **Compromise Indicators**: Unusual credential access patterns

### 3. **Malware Persistence Analysis**
- **System Hooks**: SSDT modifications indicating rootkits
- **Callback Tampering**: Driver and notification callback changes
- **Thread Injection**: Suspicious thread behavior in legitimate processes

### 4. **Timeline Correlation**
- **File Activity**: Recent file access and modification patterns
- **Resource Usage**: Open handles indicating active operations
- **Memory Mapping**: Loaded executables and suspicious regions

## Integration with Project Workflow

### Pre-Analysis (Clean System):
```bash
./vol3_artifacts.sh clean_memory.raw
```
Establishes baseline user activity, normal credentials, and clean system state.

### Post-Incident Analysis:
```bash
./vol3_artifacts.sh infected_memory.raw
```
Identifies malware artifacts, credential theft, and persistence mechanisms.

### Comparison Analysis:
Use outputs from both runs to compare:
- New user sessions (lateral movement)
- Credential access attempts
- New system hooks (rootkit installation)
- Suspicious thread injection

## Stakeholder Value

### For SOC Analysts:
- Quick identification of compromise indicators
- User session analysis for insider threat detection
- Credential security assessment

### For CSIRT Teams:
- Timeline reconstruction for incident investigation
- Malware persistence mechanism identification
- Evidence collection for threat attribution

### For Project Assessment:
- Direct alignment with project objectives
- Professional-quality forensic deliverables
- Demonstrates real-world incident response skills

## Usage Examples

### Basic Analysis:
```bash
./vol3_artifacts.sh suspicious_system.raw
```

### For Project Documentation:
1. Run script on memory image
2. Review `PROJECT_ANALYSIS_SUMMARY.txt` for report content
3. Include `timeline_summary.txt` in evidence section
4. Create manual cheat sheet from plugin outputs

## Security Considerations
- **Credential files contain sensitive data** - Handle securely
- **Hash files** - Useful for password cracking demonstrations
- **Timeline data** - Critical for incident reconstruction
- **Malware indicators** - Direct evidence of compromise

This script bridges the gap between technical memory analysis and practical incident response, providing our team with real-world forensic investigation experience.