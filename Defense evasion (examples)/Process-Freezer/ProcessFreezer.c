#include <windows.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *pNtSuspendProcess)(HANDLE ProcessHandle);
typedef NTSTATUS (NTAPI *pNtResumeProcess)(HANDLE ProcessHandle);

BOOL EnablePrivilege(LPCSTR privName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    if (!LookupPrivilegeValueA(NULL, privName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

BOOL IsSystemProcess(HANDLE hProcess) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;

    BYTE buffer[SECURITY_MAX_SID_SIZE];
    PSID systemSid = (PSID)&buffer;
    DWORD sidSize = sizeof(buffer);
    CreateWellKnownSid(WinLocalSystemSid, NULL, systemSid, &sidSize);

    BYTE tokenUserBuffer[512];
    PTOKEN_USER tokenUser = (PTOKEN_USER)tokenUserBuffer;
    DWORD len;

    BOOL isSystem = FALSE;
    if (GetTokenInformation(hToken, TokenUser, tokenUser, sizeof(tokenUserBuffer), &len)) {
        isSystem = EqualSid(systemSid, tokenUser->User.Sid);
    }

    CloseHandle(hToken);
    return isSystem;
}

void PrintIntegrityLevel(HANDLE hProcess) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        printf("Unable to query process token for integrity level.\n");
        return;
    }

    DWORD size;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &size);
    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)malloc(size);

    if (tml && GetTokenInformation(hToken, TokenIntegrityLevel, tml, size, &size)) {
        DWORD il = *GetSidSubAuthority(tml->Label.Sid, *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
        const char *level = "Unknown";

        if (il >= SECURITY_MANDATORY_SYSTEM_RID)
            level = "System";
        else if (il >= SECURITY_MANDATORY_HIGH_RID)
            level = "High";
        else if (il >= SECURITY_MANDATORY_MEDIUM_RID)
            level = "Medium";
        else if (il >= SECURITY_MANDATORY_LOW_RID)
            level = "Low";

        printf("Integrity Level: %s\n", level);
    } else {
        printf("Failed to retrieve integrity level.\n");
    }

    free(tml);
    CloseHandle(hToken);
}

void print_usage(const char *progName) {
    printf("Usage:\n");
    printf("  %s -freeze <PID>    : Suspend the process\n", progName);
    printf("  %s -unfreeze <PID>  : Resume the process\n", progName);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    if (!EnablePrivilege("SeDebugPrivilege")) {
        printf("Failed to enable SeDebugPrivilege. Try running as Administrator.\n");
        return 1;
    }

    DWORD pid = atoi(argv[2]);
    if (pid == 0) {
        printf("Invalid PID: %s\n", argv[2]);
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("Failed to open process with PID %d. Error: %lu\n", pid, GetLastError());
        return 1;
    }

    printf("Process %d opened successfully.\n", pid);
    printf("Running as SYSTEM: %s\n", IsSystemProcess(hProcess) ? "Yes" : "No");
    PrintIntegrityLevel(hProcess);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("Failed to get handle to ntdll.dll\n");
        CloseHandle(hProcess);
        return 1;
    }

    if (strcmp(argv[1], "-freeze") == 0) {
        pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
        if (!NtSuspendProcess) {
            printf("Failed to get NtSuspendProcess address\n");
            CloseHandle(hProcess);
            return 1;
        }

        NTSTATUS status = NtSuspendProcess(hProcess);
        if (status != 0) {
            printf("NtSuspendProcess failed with status: 0x%X\n", status);
        } else {
            printf("Process %d suspended successfully.\n", pid);
        }

    } else if (strcmp(argv[1], "-unfreeze") == 0) {
        pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
        if (!NtResumeProcess) {
            printf("Failed to get NtResumeProcess address\n");
            CloseHandle(hProcess);
            return 1;
        }

        NTSTATUS status = NtResumeProcess(hProcess);
        if (status != 0) {
            printf("NtResumeProcess failed with status: 0x%X\n", status);
        } else {
            printf("Process %d resumed successfully.\n", pid);
        }

    } else {
        print_usage(argv[0]);
        CloseHandle(hProcess);
        return 1;
    }

    CloseHandle(hProcess);
    return 0;
}
