#include <windows.h>
#include <tlhelp32.h>

DWORD FindProcessIdByName(CONST PCHAR ProcessName, PDWORD ProcessId)
{
    HANDLE          SnapshotHandle   = NULL;
    PROCESSENTRY32  ProcessEntry     = { NULL };

    ZeroMemory(&ProcessEntry, sizeof(PROCESSENTRY32));

    if (ProcessId == NULL) return ERROR_INVALID_PARAMETER;

    // Take a snapshot of all processes in the system.
    SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (SnapshotHandle == INVALID_HANDLE_VALUE)
    {
        return GetLastError();
    }

    ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process and exit if unsuccessful.
    if (!Process32First(SnapshotHandle, &ProcessEntry))
    {
        CloseHandle(SnapshotHandle);
        return GetLastError();
    }

    // Loop through the snapshot to find the process ID by its name.
    do
    {
        // Convert WCHAR to CHAR
        CHAR ExeName[MAX_PATH];
        ZeroMemory(ExeName, sizeof(ExeName));
        WideCharToMultiByte(CP_ACP, 0, ProcessEntry.szExeFile, -1, ExeName, sizeof(ExeName), NULL, NULL);

        if (_stricmp(ProcessName, ExeName) == 0)
        {
            *ProcessId = ProcessEntry.th32ProcessID;
            break;
        }
    } while (Process32Next(SnapshotHandle, &ProcessEntry));

    if (*ProcessId == NULL) return ERROR_NOT_FOUND;

    CloseHandle(SnapshotHandle);
    return ERROR_SUCCESS;
}

DWORD SpoofParent(CONST PCHAR ProcessName, CONST PCHAR ChildProcess)
{
    BOOL                OK                  = NULL;
    DWORD               Status              = NULL;
    DWORD               ParentProcessId     = NULL;
    HANDLE              hParentProcess      = NULL;
    SIZE_T              Size                = NULL;
    STARTUPINFOEXA      StartupInfo         = { NULL };
    PROCESS_INFORMATION ProcessInfo         = { NULL };

    StartupInfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    Status = FindProcessIdByName(ProcessName, &ParentProcessId);
    if (Status != ERROR_SUCCESS) return Status;

    hParentProcess = OpenProcess(
        PROCESS_CREATE_PROCESS,
        FALSE,
        ParentProcessId
    );

    if (!hParentProcess || hParentProcess == INVALID_HANDLE_VALUE)
        return GetLastError();

    InitializeProcThreadAttributeList(NULL, 1, 0, &Size);
    StartupInfo.lpAttributeList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
            GetProcessHeap(), 0, Size);

    InitializeProcThreadAttributeList(
        StartupInfo.lpAttributeList, 
        1, 
        0, 
        &Size
    );

    UpdateProcThreadAttribute(
        StartupInfo.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParentProcess,
        sizeof(HANDLE),
        NULL,
        NULL
    );

    OK = CreateProcessA(
        NULL,
        ChildProcess,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &StartupInfo.StartupInfo,
        &ProcessInfo
    );

    if (!OK) {
        CloseHandle(hParentProcess);
        DeleteProcThreadAttributeList(StartupInfo.lpAttributeList);
        return GetLastError();
    }

    CloseHandle(hParentProcess);
    DeleteProcThreadAttributeList(StartupInfo.lpAttributeList);
    return ERROR_SUCCESS;
}


INT main()
{
    DWORD   Status                 = NULL;
    CHAR    ParentProcessName[13]  = "explorer.exe";
    CHAR    ChildProcessName[12]   = "notepad.exe";

    Status = SpoofParent(ParentProcessName, ChildProcessName);
    
	return Status;
}

