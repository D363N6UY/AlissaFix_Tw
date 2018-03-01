// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "AlissaFix.h"

BOOL APIENTRY DllMain( HMODULE hModule,
					   DWORD  ul_reason_for_call,
					   LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(
			NULL,				//_In_opt_   LPSECURITY_ATTRIBUTES lpThreadAttributes
			0,					//_In_       SIZE_T dwStackSize,
			(LPTHREAD_START_ROUTINE)init, //_In_       LPTHREAD_START_ROUTINE lpStartAddress
			NULL,				//_In_opt_   LPVOID lpParameter
			0,					//_In_       DWORD dwCreationFlags  start right away
			NULL);				//_Out_opt_  LPDWORD lpThreadId
		
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

