#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

typedef HMODULE(WINAPI* f_LoadLibraryA)(const char* lpLibFilename);
typedef UINT_PTR(WINAPI* f_GetProcAddress)(HMODULE hModule, const char* lpProcName);
typedef BOOL(WINAPI* f_DLL_ENTY_POINT)(void* hDll, DWORD dwReason, void* pReserved);

typedef struct _MANUAL_MAPPING_DATA
{
	f_LoadLibraryA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAdress;
	HINSTANCE			hMod;
} MANUAL_MAPPING_DATA, *PMANUAL_MAPPING_DATA;

bool ManualMap(HANDLE hProc, const char* szDllFile);