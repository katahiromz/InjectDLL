#include <windows.h>
#include <windowsx.h>
#include <psapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <cassert>
#include "../config.h"
#include "../hackKit/hackKit.h"

BOOL DoCheckBits(HANDLE hProcess)
{
#ifdef _WIN64
    return isProcessWin64(hProcess);
#else
    return isProcessWin32(hProcess);
#endif
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

void OnInject(HWND hwnd, BOOL bInject)
{
    BOOL bTranslated = FALSE;
    DWORD pid = GetDlgItemInt(hwnd, edt1, &bTranslated, FALSE);
    if (!bTranslated)
    {
        MessageBox(hwnd, TEXT("Invalid PID"), NULL, MB_ICONERROR);
        return;
    }

    TCHAR szDllFile[MAX_PATH];
    GetModuleFileName(NULL, szDllFile, _countof(szDllFile));
    PathRemoveFileSpec(szDllFile);
    PathAppend(szDllFile, PAYLOAD_NAME TEXT(".dll"));
    //MessageBoxW(NULL, szDllFile, NULL, 0);

    if (bInject)
    {
        doInjectDll(szDllFile, pid);
    }
    else
    {
        doUninjectDll(szDllFile, pid);
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
    enableProcessPriviledge(SE_DEBUG_NAME);
    DialogBox(hInstance, MAKEINTRESOURCE(1), NULL, DialogProc);
    return 0;
}
