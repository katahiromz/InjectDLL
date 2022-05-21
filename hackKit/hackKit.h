#pragma once

#ifndef _INC_WINDOWS
    #include <windows.h>
#endif
#include <tlhelp32.h>
#include <vector>

BOOL isWin64(void);
BOOL isWindowsXPOrGreater(void);
BOOL isWindowsVistaOrGreater(void);
BOOL isWindowsWin32(void);
BOOL isWindowsWin64(void);
BOOL IsWow64Process(HANDLE hProcess);
BOOL isProcessWin32(HANDLE hProcess);
BOOL isProcessWin64(HANDLE hProcess);
BOOL isProcessIDWin32(DWORD dwPID);
BOOL isProcessIDWin64(DWORD dwPID);

DWORD getProcessBinaryType(HANDLE hProcess);
WORD getWindowsArchitecture(VOID);

BOOL getProcessList(std::vector<PROCESSENTRY32>& processes, DWORD dwPID = 0);
BOOL getThreadList(std::vector<THREADENTRY32>& threads, DWORD dwPID = 0, DWORD dwTID = 0);
BOOL getModuleList(std::vector<MODULEENTRY32> modules, DWORD dwPID = 0);

BOOL getProcessByName(PROCESSENTRY32& process, LPCTSTR pszName);
BOOL getModuleByName(MODULEENTRY32& module, LPCTSTR pszName, DWORD dwPID = 0);

DWORD getWindowPID(HWND hwnd);
HWND getWindowFromPID(DWORD dwPID = 0);

BOOL enableProcessPriviledge(LPCTSTR pszSE_);

BOOL doInjectDll(LPCTSTR pszDllPathName, DWORD dwPID);
BOOL doUninjectDll(LPCTSTR pszDllPathName, DWORD dwPID);
