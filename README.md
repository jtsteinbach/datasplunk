# DataSplunk: Extract Strings from Compiled Binaries

**Version**: 1.0.0
**License**: [LICENSE](https://r2.jts.gg/license)
**Developer**: [jts.gg/datasplunk](https://jts.gg/datasplunk)

---

DataSplunk is a lightweight Python utility designed to recursively scan directories for compiled executables and extract readable ASCII and hex-decoded strings. It recognizes multiple binary formats and provides fast multithreaded string mining.

Supports detection of:

* **ELF (Linux)**
* **PE/COFF (Windows)**
* **Mach-O (macOS)**
* **Java class files**

Great for malware analysis, DFIR, reverse engineering, and OSINT use cases.

## Installation

```bash
pip3 install psutil
```

## Quick Start

```bash
python3 datasplunk.py
```

Example session:

```
[Scan] Directory > /malware/samples
[Output] File Path > results.txt
[CPU] Number of threads (ex 2,4,8) > 4
```

## Features

* Auto-detects common executable signatures (ELF, PE, Mach-O, etc)
* Extracts ASCII strings and decodable hex patterns
* Multithreaded for large file sets
* Saves organized results with file headers
  
