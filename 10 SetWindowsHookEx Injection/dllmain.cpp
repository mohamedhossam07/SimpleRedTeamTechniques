// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL , (LPCWSTR)L"Injected!", NULL, 0x00000000L);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void WINAPI messageboxexport(void)
{
    MessageBox(NULL, (LPCWSTR)L"Injected from export!", NULL, 0x00000000L);
 
}