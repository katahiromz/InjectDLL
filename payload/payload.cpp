#include <windows.h>
#include "../config.h"
#include "../hackKit/hackKit.h"

// avoid LNK1104
EXTERN_C __declspec(dllexport) int
dummy(int n)
{
    return n + 1;
}

EXTERN_C BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    TCHAR szText[MAX_PATH];
    wsprintf(szText, PAYLOAD_NAME TEXT(".dll (PID:%lu)"), GetCurrentProcessId());
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, TEXT("Attached!"), szText, MB_ICONINFORMATION);
        break;

    case DLL_PROCESS_DETACH:
        MessageBox(NULL, TEXT("Detached!"), szText, MB_ICONINFORMATION);
        break;
    }
    return TRUE;
}
