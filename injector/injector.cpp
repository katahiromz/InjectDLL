#include "config.h"
#include <windows.h>
#include <windowsx.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <cassert>
#include "../config.h"

BOOL IsWow64(HANDLE hProcess)
{
    typedef BOOL (WINAPI *FN_IsWow64Process)(HANDLE, LPBOOL);
    HMODULE hKernel32 = GetModuleHandleA("kernel32");
    FN_IsWow64Process pIsWow64Process =
        (FN_IsWow64Process)GetProcAddress(hKernel32, "IsWow64Process");
    if (!pIsWow64Process)
        return FALSE;

    BOOL bWow64;
    if ((*pIsWow64Process)(hProcess, &bWow64))
        return bWow64;
    return FALSE;
}

BOOL DoCheckBits(HANDLE hProcess)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);

    switch (info.wProcessorArchitecture)
    {
#ifdef _WIN64
    case PROCESSOR_ARCHITECTURE_AMD64:
    case PROCESSOR_ARCHITECTURE_IA64:
        if (IsWow64(hProcess))
            return FALSE;
        return TRUE;
#else
    case PROCESSOR_ARCHITECTURE_INTEL:
        return TRUE;
#endif
    }
    return FALSE;
}

struct AutoCloseHandle
{
    HANDLE m_h;
    AutoCloseHandle(HANDLE h) : m_h(h)
    {
    }
    ~AutoCloseHandle()
    {
        CloseHandle(m_h);
    }
    operator HANDLE()
    {
        return m_h;
    }
};

BOOL DoInjectDLL(DWORD pid, LPCWSTR pszDllFile)
{
    AutoCloseHandle hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
    if (!hProcess)
    {
        MessageBoxW(NULL, L"!OpenProcess", NULL, MB_ICONERROR);
        return FALSE;
    }

    if (!DoCheckBits(hProcess))
    {
        MessageBoxW(NULL, L"!DoCheckBits(hProcess)", NULL, MB_ICONERROR);
        return FALSE;
    }

    DWORD cbParam = (lstrlenW(pszDllFile) + 1) * sizeof(WCHAR);
    LPVOID pParam = VirtualAllocEx(hProcess, NULL, cbParam, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pParam)
    {
        MessageBoxW(NULL, L"Out of memory!", NULL, MB_ICONERROR);
        return FALSE;
    }

    WriteProcessMemory(hProcess, pParam, pszDllFile, cbParam, NULL);

    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32"));
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW)
    {
        MessageBoxW(NULL, L"!pLoadLibraryW", NULL, MB_ICONERROR);
        VirtualFreeEx(hProcess, pParam, cbParam, MEM_RELEASE);
        return FALSE;
    }

    AutoCloseHandle hThread(CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW, pParam, 0, NULL));
    if (!hThread)
    {
        MessageBoxW(NULL, L"!CreateRemoteThread", NULL, MB_ICONERROR);
        VirtualFreeEx(hProcess, pParam, cbParam, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pParam, cbParam, MEM_RELEASE);
    return TRUE;
}

BOOL DoEnableProcessPriviledge(LPCTSTR pszSE_)
{
    BOOL f;
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    
    f = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        if (LookupPrivilegeValue(NULL, pszSE_, &luid))
        {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            tp.Privileges[0].Luid = luid;
            f = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        }
        CloseHandle(hToken);
    }
    
    return f;
}

BOOL DoGetProcessModuleInfo(LPMODULEENTRY32W pme, DWORD pid, LPCWSTR pszModule)
{
    MODULEENTRY32W me = { sizeof(me) };

    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return FALSE;

    if (Module32FirstW(hSnapshot, &me))
    {
        do
        {
            if (lstrcmpiW(me.szModule, pszModule) == 0)
            {
                *pme = me;
                CloseHandle(hSnapshot);
                return TRUE;
            }
        } while (Module32NextW(hSnapshot, &me));
    }

    return FALSE;
}

BOOL DoUninjectDLL(DWORD pid, LPCWSTR pszDllFile)
{
    AutoCloseHandle hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
    assert(hProcess);
    if (!hProcess)
    {
        MessageBoxW(NULL, L"!OpenProcess", NULL, MB_ICONERROR);
        return FALSE;
    }

    if (!DoCheckBits(hProcess))
    {
        MessageBoxW(NULL, L"!DoCheckBits(hProcess)", NULL, MB_ICONERROR);
        return FALSE;
    }

    MODULEENTRY32W me;
    if (!DoGetProcessModuleInfo(&me, pid, PathFindFileNameW(pszDllFile)))
    {
        assert(0);
        return FALSE;
    }
    HMODULE hModule = me.hModule;

    HMODULE hNTDLL = GetModuleHandle(TEXT("ntdll"));
    FARPROC pLdrUnloadDll = GetProcAddress(hNTDLL, "LdrUnloadDll");
    if (!pLdrUnloadDll)
    {
        MessageBoxW(NULL, L"!pLdrUnloadDll", NULL, MB_ICONERROR);
        return FALSE;
    }

    AutoCloseHandle hThread(CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLdrUnloadDll, hModule, 0, NULL));
    if (!hThread)
    {
        MessageBoxW(NULL, L"!CreateRemoteThread", NULL, MB_ICONERROR);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    return TRUE;
}

void OnInject(HWND hwnd, BOOL bInject)
{
    BOOL bTranslated = FALSE;
    DWORD pid = GetDlgItemInt(hwnd, edt1, &bTranslated, FALSE);
    if (!bTranslated)
    {
        MessageBoxW(hwnd, L"Invalid PID", NULL, MB_ICONERROR);
        return;
    }

    WCHAR szDllFile[MAX_PATH];
    GetModuleFileNameW(NULL, szDllFile, MAX_PATH);
    PathRemoveFileSpecW(szDllFile);
    PathAppendW(szDllFile, PAYLOAD_NAME L".dll");
    //MessageBoxW(NULL, szDllFile, NULL, 0);

    if (bInject)
    {
        DoInjectDLL(pid, szDllFile);
    }
    else
    {
        DoUninjectDLL(pid, szDllFile);
    }
}

BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
    return TRUE;
}

void OnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
    switch (id)
    {
    case IDOK:
    case IDCANCEL:
        EndDialog(hwnd, id);
        break;
    case psh1:
        OnInject(hwnd, TRUE);
        break;
    case psh2:
        OnInject(hwnd, FALSE);
        break;
    }
}

INT_PTR CALLBACK
DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        HANDLE_MSG(hwnd, WM_INITDIALOG, OnInitDialog);
        HANDLE_MSG(hwnd, WM_COMMAND, OnCommand);
    }
    return 0;
}

INT WINAPI
WinMain(HINSTANCE   hInstance,
        HINSTANCE   hPrevInstance,
        LPSTR       lpCmdLine,
        INT         nCmdShow)
{
    DoEnableProcessPriviledge(SE_DEBUG_NAME);
    DialogBoxW(hInstance, MAKEINTRESOURCEW(1), NULL, DialogProc);
    return 0;
}
