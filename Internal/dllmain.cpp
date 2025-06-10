// Tensora Softworks
#include <Windows.h>

#include "hooks_vm.hpp"
#include "hooks_key.hpp"
BOOL cal = 0;
void _main() {
    if (cal) { return; }
    cal = 1;

    //im too lazy to make the function take a function ptr and name btw. so yes, i wrote 5 instead!
    hookZwSetValueKey();
    hookZwDeleteValueKey();

    hookZwCreateKey();
    hookZwDeleteKey();
    hookZwOpenKey();

    while (1) {

    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)_main, 0, 0, 0);
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

