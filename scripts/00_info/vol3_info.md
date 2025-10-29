# vol3_info.sh - Memory Baseline Metadata Extraction Script

**Script Location:** `./vol3_info.sh`  
**Usage:** `./vol3_info.sh PATH_TO_MEMORY_IMAGE`  
**Purpose:** Extracts baseline metadata from a memory image including OS, version info, MBR (optional), and timezone registry information. Outputs are saved in `outputs/<image>_<timestamp>/00_info/`.

---

## Overview

This script runs a small set of Volatility3 plugins to capture foundational system information. The outputs serve as the baseline context for further forensic analysis and are essential for documenting the environment in which the memory image was captured.

**Key Points:**
- Extracts operating system and kernel details.
- Retrieves version information for reference.
- Optionally extracts MBR if present.
- Extracts the system timezone from the registry.
- Saves all outputs and a README summary for traceability.

---

## Plugins Executed

### 1. `windows.info`
**What it does:**  
Collects basic system metadata from the memory image, including OS name, build number, architecture, and general configuration details.

**Forensic / Analysis Purpose:**  
Provides a clear snapshot of the system environment. Helps analysts confirm that the memory image corresponds to the expected system and is compatible with further plugins.

---

### 2. `windows.verinfo`
**What it does:**  
Retrieves detailed Windows version and build information from the memory image, including service pack and edition details.

**Forensic / Analysis Purpose:**  
Useful for understanding the target environment, validating compatibility with other plugins, and identifying potential version-specific exploits or artifacts.

---

### 3. `windows.mbr` (optional)
**What it does:**  
Extracts the Master Boot Record from memory, if present.

**Forensic / Analysis Purpose:**  
Can reveal boot-level malware or rootkits. While not present in all memory images, MBR extraction helps analysts detect tampering with the boot sector or partition table.

---

### 4. `windows.printkey` (Timezone Registry Key)
**What it does:**  
Reads the registry key `ControlSet001\Control\TimeZoneInformation` from memory to extract the system’s configured timezone.

**Forensic / Analysis Purpose:**  
Supports timeline correlation of system events across multiple timezones. Ensures accurate timestamp interpretation in process execution, log entries, and network activity analysis.

---

## Output Structure

All plugin outputs are saved as plain text files in a timestamped directory:
