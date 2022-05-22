#include "hackKit.h"
#include <psapi.h>
#include <shlwapi.h>
#include <imagehlp.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <tchar.h>
#include "../config.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "imagehlp.lib")

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
    operator HANDLE&()
    {
        return m_h;
    }
};

BOOL isWin64(void)
{
#ifdef _WIN64
    return TRUE;
#else
    return FALSE;
#endif
}

BOOL isWindowsXPOrGreater(void)
{
    OSVERSIONINFO osver = { sizeof(osver) };
    GetVersionEx(&osver);
    if (osver.dwMajorVersion >= 6)
        return TRUE;
    if (osver.dwMajorVersion == 5 && osver.dwMinorVersion >= 1)
        return TRUE;
    return FALSE;
}

BOOL isWindowsVistaOrGreater(void)
{
    OSVERSIONINFO osver = { sizeof(osver) };
    GetVersionEx(&osver);
    return osver.dwMajorVersion >= 6;
}

typedef BOOL (WINAPI *FN_IsWow64Process)(HANDLE, PBOOL);
typedef VOID (WINAPI *FN_GetNativeSystemInfo)(SYSTEM_INFO*);

BOOL IsWow64Process(HANDLE hProcess)
{
    if (hProcess == NULL)
        hProcess = GetCurrentProcess();

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

DWORD getProcessBinaryType(HANDLE hProcess)
{
    if (hProcess == NULL)
        hProcess = GetCurrentProcess();

    TCHAR szPath[MAX_PATH];
    if (!GetModuleFileNameEx(hProcess, NULL, szPath, _countof(szPath)))
        return -1;

    DWORD dwType;
    if (!GetBinaryType(szPath, &dwType))
        return -1;

    return dwType;
}

BOOL isProcessWin32(HANDLE hProcess)
{
    if (hProcess == NULL)
        hProcess = GetCurrentProcess();
    if (IsWow64Process(hProcess))
        return TRUE;
    return getProcessBinaryType(hProcess) == SCS_32BIT_BINARY;
}

BOOL isProcessWin64(HANDLE hProcess)
{
    if (hProcess == NULL)
        hProcess = GetCurrentProcess();
    if (IsWow64Process(hProcess))
        return FALSE;
    return getProcessBinaryType(hProcess) == SCS_64BIT_BINARY;
}

BOOL isProcessIDWin32(DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();
    AutoCloseHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID));
    return isProcessWin32(hProcess);
}

BOOL isProcessIDWin64(DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();
    AutoCloseHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID));
    return isProcessWin64(hProcess);
}

WORD getWindowsArchitecture(VOID)
{
    HINSTANCE hKernel32 = GetModuleHandleA("kernel32");

    SYSTEM_INFO sysinfo;

    FN_GetNativeSystemInfo fnGetNativeSystemInfo;
    fnGetNativeSystemInfo = (FN_GetNativeSystemInfo)GetProcAddress(hKernel32, "GetNativeSystemInfo");
    if (fnGetNativeSystemInfo)
    {
        fnGetNativeSystemInfo(&sysinfo);
        return sysinfo.wProcessorArchitecture;
    }

    GetSystemInfo(&sysinfo);
    return sysinfo.wProcessorArchitecture;
}

BOOL isWindowsWin32(void)
{
    return getWindowsArchitecture() == PROCESSOR_ARCHITECTURE_INTEL;
}

BOOL isWindowsWin64(void)
{
    return getWindowsArchitecture() == PROCESSOR_ARCHITECTURE_AMD64;
}

BOOL getProcessList(std::vector<PROCESSENTRY32>& processes, DWORD dwPID)
{
    processes.clear();

    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        puts("getProcessList: FAILED");
        assert(0);
        return FALSE;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            if (dwPID == 0)
            {
                processes.push_back(pe);
            }
            else if (dwPID == pe.th32ProcessID)
            {
                processes.push_back(pe);
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    return !processes.empty();
}

BOOL getThreadList(std::vector<THREADENTRY32>& threads, DWORD dwPID, DWORD dwTID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    threads.clear();

    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPID));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        puts("getThreadList: FAILED");
        assert(0);
        return FALSE;
    }

    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnapshot, &te))
    {
        do
        {
            if (dwTID == 0)
            {
                threads.push_back(te);
            }
            else if (dwTID == te.th32ThreadID)
            {
                threads.push_back(te);
                break;
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    return !threads.empty();
}

BOOL getModuleList(std::vector<MODULEENTRY32>& modules, DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        puts("getModuleList: FAILED");
        assert(0);
        return FALSE;
    }

    MODULEENTRY32 me = { sizeof(me) };

    if (Module32First(hSnapshot, &me))
    {
        do
        {
            modules.push_back(me);
        } while (Module32Next(hSnapshot, &me));
    }

    return TRUE;
}

BOOL getModuleByName(MODULEENTRY32& module, LPCTSTR pszName, DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        puts("getModuleByName: FAILED");
        assert(0);
        return FALSE;
    }

    pszName = PathFindFileName(pszName);

    MODULEENTRY32 me = { sizeof(me) };

    if (Module32First(hSnapshot, &me))
    {
        do
        {
            if (lstrcmpi(me.szModule, pszName) == 0)
            {
                module = me;
                return TRUE;
            }
        } while (Module32Next(hSnapshot, &me));
    }

    puts("getModuleByName: FAILED");
    return FALSE;
}

BOOL getProcessByName(PROCESSENTRY32& process, LPCTSTR pszName)
{
    AutoCloseHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        puts("getProcessByName: FAILED");
        assert(0);
        return FALSE;
    }

    pszName = PathFindFileName(pszName);

    PROCESSENTRY32 pe = { sizeof(pe) };

    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            if (lstrcmpi(pe.szExeFile, pszName) == 0)
            {
                process = pe;
                return TRUE;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    puts("getProcessByName: FAILED");
    return FALSE;
}

BOOL doInjectDll(LPCTSTR pszDllPathName, DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    AutoCloseHandle hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID));
    if (!hProcess)
    {
        puts("doInjectDll: !OpenProcess");
        assert(0);
        return FALSE;
    }

    if (isWin64())
    {
        if (!isProcessWin64(hProcess))
        {
            puts("doInjectDll: !isProcessWin64");
            assert(0);
            return FALSE;
        }
    }
    else
    {
        if (!isProcessWin32(hProcess))
        {
            puts("doInjectDll: !isProcessWin32");
            assert(0);
            return FALSE;
        }
    }

    DWORD cbParam = (lstrlen(pszDllPathName) + 1) * sizeof(TCHAR);
    LPVOID pParam = VirtualAllocEx(hProcess, NULL, cbParam, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pParam)
    {
        puts("doInjectDll: !VirtualAllocEx");
        assert(0);
        return FALSE;
    }

    WriteProcessMemory(hProcess, pParam, pszDllPathName, cbParam, NULL);

    HMODULE hKernel32 = GetModuleHandleA("kernel32");
#ifdef UNICODE
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
#else
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
#endif
    if (!pLoadLibrary)
    {
        puts("doInjectDll: !pLoadLibrary");
        assert(0);
        VirtualFreeEx(hProcess, pParam, cbParam, MEM_RELEASE);
        return FALSE;
    }

    AutoCloseHandle hThread(CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, pParam, 0, NULL));
    if (!hThread)
    {
        puts("doInjectDll: !hThread");
        assert(0);
        VirtualFreeEx(hProcess, pParam, cbParam, MEM_RELEASE);
        return FALSE;
    }

    if (WaitForSingleObject(hThread, INFINITE) == WAIT_ABANDONED)
    {
        puts("doInjectDll: !WaitForSingleObject");
        assert(0);
    }

    VirtualFreeEx(hProcess, pParam, cbParam, MEM_RELEASE);
    return TRUE;
}

BOOL doUninjectDll(LPCTSTR pszDllPathName, DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    AutoCloseHandle hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID));
    if (!hProcess)
    {
        puts("doUninjectDll: !OpenProcess");
        assert(0);
        return FALSE;
    }

    if (isWin64())
    {
        if (!isProcessWin64(hProcess))
        {
            puts("doUninjectDll: !isProcessWin64");
            assert(0);
            return FALSE;
        }
    }
    else
    {
        if (!isProcessWin32(hProcess))
        {
            puts("doUninjectDll: !isProcessWin32");
            assert(0);
            return FALSE;
        }
    }

    LPCTSTR pszDllName = PathFindFileName(pszDllPathName);

    MODULEENTRY32 me = { sizeof(me) };
    if (!getModuleByName(me, pszDllName, dwPID))
    {
        puts("doUninjectDll: !getModuleByName");
        assert(0);
        return FALSE;
    }

    HMODULE hModule = me.hModule;

    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    FARPROC pLdrUnloadDll = GetProcAddress(hNTDLL, "LdrUnloadDll");
    if (!pLdrUnloadDll)
    {
        puts("doUninjectDll: !pLdrUnloadDll");
        assert(0);
        return FALSE;
    }

    AutoCloseHandle hThread(CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLdrUnloadDll, hModule, 0, NULL));
    if (!hThread)
    {
        puts("doUninjectDll: !hThread");
        assert(0);
        return FALSE;
    }

    if (WaitForSingleObject(hThread, INFINITE) == WAIT_ABANDONED)
    {
        puts("doUninjectDll: !WaitForSingleObject");
        assert(0);
    }

    return TRUE;
}

DWORD getWindowPID(HWND hwnd)
{
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

BOOL enableProcessPriviledge(LPCTSTR pszSE_)
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

struct WNDANDPID
{
    HWND hwnd;
    DWORD pid;
};

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    DWORD pid = getWindowPID(hwnd);
    WNDANDPID *pInfo = (WNDANDPID *)lParam;
    if (pInfo->pid == pid)
    {
        pInfo->hwnd = hwnd;
        return FALSE;
    }

    EnumChildWindows(hwnd, EnumWindowsProc, lParam);
    if (pInfo->hwnd)
        return FALSE;
    return TRUE;
}

HWND getWindowFromPID(DWORD dwPID)
{
    if (dwPID == 0)
        dwPID = GetCurrentProcessId();

    WNDANDPID info = { NULL, dwPID };
    EnumWindows(EnumWindowsProc, (LPARAM)&info);
    return info.hwnd;
}

BOOL getSameFolderPathName(LPTSTR pszPathName, LPCTSTR pszFileTitle)
{
    GetModuleFileName(NULL, pszPathName, MAX_PATH);
    PathRemoveFileSpec(pszPathName);
    PathAppend(pszPathName, pszFileTitle);
    return TRUE;
}

static LPVOID
doImportTable(HMODULE hModule, PIMAGE_IMPORT_DESCRIPTOR pImport, LPCSTR pszFuncName, LPVOID fnNew)
{
    LPBYTE pbBase = (LPBYTE)hModule;
    for (; pImport->OriginalFirstThunk; pImport++)
    {
        LPCSTR pszDllName = (LPCSTR)(pbBase + pImport->Name);
        PIMAGE_THUNK_DATA pThunc, pOriginalThunk;
        pThunc = (PIMAGE_THUNK_DATA)(pbBase + pImport->FirstThunk);
        pOriginalThunk = (PIMAGE_THUNK_DATA)(pbBase + pImport->OriginalFirstThunk);
        for (; pThunc->u1.Function; ++pThunc, ++pOriginalThunk)
        {
            if (HIWORD(pszFuncName) == 0)
            {
                if (!IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
                    continue;

                WORD wOrdinal = IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal);
                if (wOrdinal != LOWORD(pszFuncName))
                    continue;
            }
            else
            {
                if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
                    continue;

                PIMAGE_IMPORT_BY_NAME pName =
                    (PIMAGE_IMPORT_BY_NAME)(pbBase + pOriginalThunk->u1.AddressOfData);
                if (stricmp((LPCSTR)pName->Name, pszFuncName) != 0)
                    continue;
            }

            DWORD dwOldProtect;
            if (!VirtualProtect(&pThunc->u1.Function, sizeof(pThunc->u1.Function),
                                PAGE_READWRITE, &dwOldProtect))
                return NULL;

            LPVOID fnOriginal = (LPVOID)(ULONG_PTR)pThunc->u1.Function;
            WriteProcessMemory(GetCurrentProcess(), &pThunc->u1.Function, &fnNew,
                               sizeof(pThunc->u1.Function), NULL);
            pThunc->u1.Function = (ULONG_PTR)fnNew;

            VirtualProtect(&pThunc->u1.Function, sizeof(pThunc->u1.Function),
                           dwOldProtect, &dwOldProtect);
            return fnOriginal;
        }
    }

    return NULL;
}

LPVOID doHookAPI(HMODULE hModule, LPCSTR pszModuleName, LPCSTR pszFuncName, LPVOID fnNew)
{
    if (!fnNew)
        return NULL;
    if (!pszFuncName)
        return NULL;
    if (!hModule)
        hModule = GetModuleHandleA(NULL);

    DWORD dwSize;
    PIMAGE_IMPORT_DESCRIPTOR pImport;
    pImport = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
        hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &dwSize);
    LPVOID fnOriginal = doImportTable(hModule, pImport, pszFuncName, fnNew);
    if (fnOriginal)
        return fnOriginal;

    return NULL;
}

BOOL startProcess(LPCTSTR cmdline, STARTUPINFO& si, PROCESS_INFORMATION& pi,
                  DWORD dwCreation, LPCTSTR pszCurDir)
{
    assert(cmdline);
    LPTSTR pszCmdLine = _tcsdup(cmdline);
    assert(pszCmdLine);
    BOOL ret = CreateProcess(NULL, pszCmdLine, NULL, NULL, TRUE, dwCreation, NULL, pszCurDir, &si, &pi);
    free(pszCmdLine);
    return ret;
}
