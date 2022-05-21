#include <windows.h>
#include "../config.h"

// avoid LNK1104
EXTERN_C __declspec(dllexport) int
dummy(int n)
{
    return n + 1;
}

EXTERN_C BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    WCHAR szText[MAX_PATH];
    wsprintfW(szText, PAYLOAD_NAME L".dll (PID:%lu)", GetCurrentProcessId());
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxW(NULL, L"Attached!", szText, MB_ICONINFORMATION);
        break;

    case DLL_PROCESS_DETACH:
        MessageBoxW(NULL, L"Detached!", szText, MB_ICONINFORMATION);
        break;
    }
    return TRUE;
}
