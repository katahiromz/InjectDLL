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
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxW(NULL, L"Attached!", PAYLOAD_NAME L".dll", MB_ICONINFORMATION);
        break;

    case DLL_PROCESS_DETACH:
        MessageBoxW(NULL, L"Detached!", PAYLOAD_NAME L".dll", MB_ICONINFORMATION);
        break;
    }
    return TRUE;
}
