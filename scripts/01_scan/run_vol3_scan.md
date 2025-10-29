# Volatility3 Scan Script - Process & Network Analysis

## Overview
`run_vol3_scan.sh` performs comprehensive process, network, and malware detection analysis on Windows memory images using Volatility3. This script is designed for the scanning phase of forensic analysis, focusing on active processes, network connections, and potential malware artifacts.

## Purpose
This script is part of a structured forensic analysis workflow:
- **Phase 00**: Baseline information extraction (`vol3_info.sh`)
- **Phase 01**: Process and network scanning (`run_vol3_scan.sh`) (This script)
- **Phase 02**: Registry analysis (`vol3_registry.sh`)

## Usage
```bash
./run_vol3_scan.sh PATH_TO_MEMORY_IMAGE
```

### Example
```bash
./run_vol3_scan.sh /path/to/memory.raw
./run_vol3_scan.sh suspicious_system.mem
```

## Plugins Executed

### Process Analysis
| Plugin | Description | Malware Detection Value |
|--------|-------------|------------------------|
| `windows.pslist` | Lists active processes | Identifies suspicious running processes |
| `windows.psscan` | Scans for hidden/terminated processes | Finds process hiding techniques |
| `windows.cmdline` | Shows command line arguments | Reveals malware execution parameters |
| `windows.dlllist` | Lists loaded DLLs per process | Detects DLL injection/hijacking |

### Network Analysis
| Plugin | Description | Malware Detection Value |
|--------|-------------|------------------------|
| `windows.netscan` | Network connections and listening ports | Identifies C&C communications, backdoors |

### Malware Detection
| Plugin | Description | Malware Detection Value |
|--------|-------------|------------------------|
| `windows.malfind` | Suspicious memory regions | Detects code injection, packed malware |

### User Activity Analysis
| Plugin | Description | Malware Detection Value |
|--------|-------------|------------------------|
| `windows.consoles` | Console windows and command history | Shows recent user/malware commands |
| `windows.cmdscan` | Recovers deleted command history | Finds hidden execution traces |
| `windows.envars` | Environment variables | Reveals malware paths and configurations |

## Output Structure
```
outputs/
└── <image_name>_<timestamp>/
    ├── <image>_windows_pslist.txt
    ├── <image>_windows_psscan.txt
    ├── <image>_windows_netscan.txt
    ├── <image>_windows_cmdline.txt
    ├── <image>_windows_dlllist.txt
    ├── <image>_windows_malfind.txt
    ├── <image>_windows_consoles.txt
    ├── <image>_windows_cmdscan.txt
    ├── <image>_windows_envars.txt
    └── README.txt
```

## Pre vs Post Malware Analysis

### Pre-Malware (Baseline)
- Documents legitimate running processes
- Records normal network connections
- Establishes baseline of loaded DLLs
- Shows normal memory allocation patterns
- Records legitimate command line usage
- Captures clean environment variables

### Post-Malware (Detection)
- **Process Analysis**: New/suspicious processes, process hiding, hollowing
- **Network Analysis**: C&C communications, backdoor listeners, data exfiltration
- **Code Injection**: Injected malicious code, DLL hijacking, reflective loading
- **Persistence**: Command lines reveal startup mechanisms
- **Environment**: Modified paths, malware-specific variables