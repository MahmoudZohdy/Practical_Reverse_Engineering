#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

#define APC_ENUMERATION 0x8036
#define IOCTL_APC_ENUMERATION CTL_CODE(APC_ENUMERATION, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

DWORD64 Threadarray[1000];
int counter = 1;
DWORD64 PID = 0;
//  Forward declarations:
VOID ListProcessThreads(DWORD dwOwnerPID);
void printError(WCHAR* msg);
int main(int argc, char* argv[])
{
    DWORD returned;
    PID = atoi((const char*)argv[1]);

    HANDLE hDevice = CreateFileA("\\\\.\\APCEnumeration", GENERIC_WRITE, FILE_SHARE_WRITE, FALSE, OPEN_EXISTING, 0, FALSE);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed To Open Driver Error Code: 0x%x\n", GetLastError());
        return 0;
    }

    typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
    typedef LONG(NTAPI* pNtResumeProcess)(IN HANDLE ProcessHandle);

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
        GetModuleHandle(L"ntdll"), "NtSuspendProcess");

    pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(
        GetModuleHandle(L"ntdll"), "NtResumeProcess");


    //will be used in the kernel Driver as user-mode function in the APC enumeration
    Threadarray[0] = (DWORD64)GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryA");

    pfnNtSuspendProcess(processHandle);

    ListProcessThreads(PID);//GetCurrentProcessId()

    BOOL Status = DeviceIoControl(hDevice, IOCTL_APC_ENUMERATION, Threadarray, sizeof(DWORD64) * 1000, NULL, NULL, &returned, FALSE);
    if (!Status) {
        printf("[-] Failed to Enumerate APC Error Code: 0x%x\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Success in Enumerating all APC in Process ID %d\n", PID);

cleanup:

    NtResumeProcess(processHandle);

    CloseHandle(processHandle);
    CloseHandle(hDevice);

    //it suspend hear for long time do not know why
    ExitProcess(0);

    return 0;
}

VOID ListProcessThreads(DWORD dwOwnerPID)
{
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return(FALSE);

    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32))
    {
        printError((WCHAR*)L"Thread32First");
        CloseHandle(hThreadSnap);
        return(FALSE);
    }

    do
    {
        if (te32.th32OwnerProcessID == dwOwnerPID)
        {
            _tprintf(TEXT("\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
            _tprintf(TEXT("\n     base priority  = %d"), te32.tpBasePri);
            _tprintf(TEXT("\n     delta priority = %d"), te32.tpDeltaPri);

            Threadarray[counter] = te32.th32ThreadID;
            counter++;
        }
    } while (Thread32Next(hThreadSnap, &te32));

    _tprintf(TEXT("\n"));

    CloseHandle(hThreadSnap);
    return(TRUE);
}

void printError(WCHAR* msg)
{
    DWORD eNum;
    TCHAR sysMsg[256];
    TCHAR* p;

    eNum = GetLastError();
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
        sysMsg, 256, NULL);

    // Trim the end of the line and terminate it with a null
    p = sysMsg;
    while ((*p > 31) || (*p == 9))
        ++p;
    do { *p-- = 0; } while ((p >= sysMsg) &&
        ((*p == '.') || (*p < 33)));

    // Display the message
    _tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}