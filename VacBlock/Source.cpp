#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <detours.h>

#include "MemoryUtils.h"

#pragma comment(lib, "detours.lib")

#define VAC_LOADLIBRARY_FORCE_SIGNATURE "\x74\x47\x6A\x01\x6A"
#define LOGFILE_A "C:\\Users\\Riza\\Desktop\\vaclog.txt"

//#define LOG_ONLY

typedef HMODULE(WINAPI* LoadLibraryExW_t)(
	LPCWSTR,
	HANDLE,
	DWORD
);

LoadLibraryExW_t originalLoadLibrary;
FILE* log;
HMODULE self;

VOID WriteLog(const char* data, ...) {
	log = fopen(LOGFILE_A, "a");

	va_list args;
	va_start(args, data);

	vfprintf(log, data, args);
	fwrite(data, strlen(data), 1, log);
	fclose(log);

	va_end(args);
}

HMODULE WINAPI HookedLoadLibrary(LPCWSTR lpLibFileName, HANDLE  hFile, DWORD dwFlags) {

	HMODULE loadedModule = originalLoadLibrary(lpLibFileName, hFile, dwFlags);

	PVOID runfunc = GetProcAddress(loadedModule, "_runfunc@20");

	if (runfunc) {

#ifndef LOG_ONLY
		WriteLog("[*] Blocking VAC loader thread ...\n");
		SuspendThread(GetCurrentThread());
#else
		WriteLog("[*] _runfunc: %p\n", runfunc);
#endif

		return 0;
	}

	return loadedModule;
}

VOID PatchVACLoader() {

	Module steamService;
	GetModule("SteamService.dll", &steamService);

	DWORD foundAddress = SearchForSignature(
		steamService.base,
		(unsigned char*)VAC_LOADLIBRARY_FORCE_SIGNATURE, 
		5,
		steamService.size
	);

	DWORD oldProtection = 0;

	VirtualProtect((LPVOID)foundAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtection);
	*(BYTE*)foundAddress = 0xEB;
	VirtualProtect((LPVOID)foundAddress, 1, oldProtection, &oldProtection);


}

VOID HookLoadLibrary() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	HMODULE kernel = GetModuleHandleA("kernel32.dll");

	originalLoadLibrary =
		(LoadLibraryExW_t)GetProcAddress(kernel, "LoadLibraryExW");

	DetourAttach(&(PVOID&)originalLoadLibrary, HookedLoadLibrary);

	DetourTransactionCommit();
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
) {

	if (fdwReason != DLL_PROCESS_ATTACH) {
		return TRUE;
	}

	self = hinstDLL;

	log = fopen(LOGFILE_A, "w");
	fwrite("[*] Starting VacBlocker v0.1\n", strlen("[*] Starting VacBlocker v0.1\n") , 1, log);
	fclose(log);

	WriteLog("[*] Hooking LoadLibraryW ...\n");
	HookLoadLibrary();

	WriteLog("[*] Patching SteamService.dll ...\n");
	PatchVACLoader();

	fclose(log);

	return TRUE;
}