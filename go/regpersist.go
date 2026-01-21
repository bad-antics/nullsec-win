// NullSec Windows Registry Persistence
// Registry-based persistence and enumeration
// Build: GOOS=windows go build -o nullsec-regpersist.exe regpersist.go
package main

import (
	"flag"
	"fmt"
	"os/exec"
	"strings"
)

func banner() {
	fmt.Println(`
╔═══════════════════════════════════════╗
║   NullSec Registry Persist - Win      ║
║   Fast Go-based registry manipulation ║
╚═══════════════════════════════════════╝`)
}

type RegKey struct {
	Path  string
	Name  string
	Value string
}

var persistenceKeys = []string{
	`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
	`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
	`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`,
	`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`,
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
	`HKCU\Environment`,
}

func runReg(args ...string) (string, error) {
	cmd := exec.Command("reg", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func queryKey(keyPath string) []RegKey {
	var keys []RegKey
	out, err := runReg("query", keyPath)
	if err != nil {
		return keys
	}
	
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, keyPath) {
			continue
		}
		
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			keys = append(keys, RegKey{
				Path:  keyPath,
				Name:  parts[0],
				Value: strings.Join(parts[2:], " "),
			})
		}
	}
	return keys
}

func listPersistence() {
	fmt.Println("\n[*] Checking persistence registry keys...\n")
	
	for _, keyPath := range persistenceKeys {
		fmt.Printf("[%s]\n", keyPath)
		keys := queryKey(keyPath)
		
		if len(keys) == 0 {
			fmt.Println("    (empty or access denied)")
		} else {
			for _, k := range keys {
				// Truncate long values
				val := k.Value
				if len(val) > 60 {
					val = val[:60] + "..."
				}
				fmt.Printf("    %s = %s\n", k.Name, val)
			}
		}
		fmt.Println()
	}
}

func addPersistence(name, value string, hklm bool) error {
	keyPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	if hklm {
		keyPath = `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
	}
	
	_, err := runReg("add", keyPath, "/v", name, "/t", "REG_SZ", "/d", value, "/f")
	if err != nil {
		return fmt.Errorf("failed to add key: %v", err)
	}
	
	fmt.Printf("[✓] Added persistence: %s\\%s = %s\n", keyPath, name, value)
	return nil
}

func removePersistence(name string, hklm bool) error {
	keyPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	if hklm {
		keyPath = `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
	}
	
	_, err := runReg("delete", keyPath, "/v", name, "/f")
	if err != nil {
		return fmt.Errorf("failed to remove key: %v", err)
	}
	
	fmt.Printf("[✓] Removed: %s\\%s\n", keyPath, name)
	return nil
}

func addEnvironmentPath(path string) error {
	// Add to user PATH
	out, _ := runReg("query", `HKCU\Environment`, "/v", "Path")
	
	currentPath := ""
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Path") && strings.Contains(line, "REG_") {
			parts := strings.SplitN(line, "REG_EXPAND_SZ", 2)
			if len(parts) > 1 {
				currentPath = strings.TrimSpace(parts[1])
			} else {
				parts = strings.SplitN(line, "REG_SZ", 2)
				if len(parts) > 1 {
					currentPath = strings.TrimSpace(parts[1])
				}
			}
		}
	}
	
	newPath := currentPath + ";" + path
	_, err := runReg("add", `HKCU\Environment`, "/v", "Path", "/t", "REG_EXPAND_SZ", "/d", newPath, "/f")
	
	if err != nil {
		return err
	}
	
	fmt.Printf("[✓] Added to PATH: %s\n", path)
	return nil
}

func dumpSAM() {
	fmt.Println("\n[*] SAM Database (requires SYSTEM):")
	fmt.Println("    Location: C:\\Windows\\System32\\config\\SAM")
	fmt.Println("    Use: reg save HKLM\\SAM sam.hive")
	fmt.Println("    Or:  secretsdump.py -sam sam.hive -system system.hive LOCAL")
}

func main() {
	banner()
	
	list := flag.Bool("list", false, "List persistence keys")
	add := flag.String("add", "", "Add persistence (name)")
	value := flag.String("value", "", "Value/command for persistence")
	remove := flag.String("remove", "", "Remove persistence key")
	hklm := flag.Bool("hklm", false, "Use HKLM instead of HKCU (requires admin)")
	path := flag.String("path", "", "Add directory to PATH")
	sam := flag.Bool("sam", false, "Show SAM dump info")
	flag.Parse()
	
	if *list {
		listPersistence()
		return
	}
	
	if *add != "" && *value != "" {
		if err := addPersistence(*add, *value, *hklm); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
		}
		return
	}
	
	if *remove != "" {
		if err := removePersistence(*remove, *hklm); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
		}
		return
	}
	
	if *path != "" {
		if err := addEnvironmentPath(*path); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
		}
		return
	}
	
	if *sam {
		dumpSAM()
		return
	}
	
	fmt.Println("[!] Usage:")
	fmt.Println("    nullsec-regpersist -list")
	fmt.Println("    nullsec-regpersist -add <name> -value <command>")
	fmt.Println("    nullsec-regpersist -remove <name>")
	fmt.Println("    nullsec-regpersist -path <directory>")
	flag.PrintDefaults()
}
