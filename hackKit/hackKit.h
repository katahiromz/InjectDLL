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
BOOL IsWow64Process(HANDLE hProcess = NULL);
BOOL isProcessWin32(HANDLE hProcess = NULL);
BOOL isProcessWin64(HANDLE hProcess = NULL);
BOOL isProcessIDWin32(DWORD dwPID = 0);
BOOL isProcessIDWin64(DWORD dwPID = 0);

DWORD getProcessBinaryType(HANDLE hProcess = NULL);
WORD getWindowsArchitecture(VOID);

BOOL getProcessList(std::vector<PROCESSENTRY32>& processes, DWORD dwPID = 0);
BOOL getThreadList(std::vector<THREADENTRY32>& threads, DWORD dwPID = 0, DWORD dwTID = 0);
BOOL getModuleList(std::vector<MODULEENTRY32>& modules, DWORD dwPID = 0);

BOOL getProcessByName(PROCESSENTRY32& process, LPCTSTR pszName);
BOOL getModuleByName(MODULEENTRY32& module, LPCTSTR pszName, DWORD dwPID = 0);

DWORD getWindowPID(HWND hwnd);
HWND getWindowFromPID(DWORD dwPID = 0);

BOOL enableProcessPriviledge(LPCTSTR pszSE_);

BOOL doInjectDll(LPCTSTR pszDllPathName, DWORD dwPID = 0);
BOOL doUninjectDll(LPCTSTR pszDllPathName, DWORD dwPID = 0);
BOOL getSameFolderPathName(LPTSTR pszPathName, LPCTSTR pszFileTitle);

LPVOID doHookAPI(HMODULE hTargetModule, LPCSTR pszModuleName, LPCSTR pszFuncName, LPVOID fnNew);
BOOL startProcess(LPCTSTR cmdline, STARTUPINFO& si, PROCESS_INFORMATION& pi,
                  DWORD dwCreation = 0, LPCTSTR pszCurDir = NULL);
