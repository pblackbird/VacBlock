#include "MemoryUtils.h"

DWORD SearchForSignature(DWORD start, unsigned char* pattern, SIZE_T sizeOfPattern, SIZE_T size) {

	SIZE_T position = start;
	DWORD res = 0;

	while (position < start + size) {
		if (memcmp((const void*)(position), pattern, sizeOfPattern) != 0) {
			position++;
			continue;
		}

		res = position;
		break;
	}

	return res;
}

DWORD GetModule(CONST CHAR* dllName, Module* mdl) {
	DWORD bytesRequired;
	HMODULE* modules;
	DWORD addr = 0;

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	if (process == NULL) {
		DWORD lastError = GetLastError();
		CloseHandle(process);

		return 0;
	}

	BOOL result = EnumProcessModules(process, 0, 0, &bytesRequired);

	if (!result) {
		DWORD lastError = GetLastError();
		CloseHandle(process);

		return 0;
	}

	modules = (HMODULE*)malloc(bytesRequired);

	unsigned int moduleCount;

	moduleCount = bytesRequired / sizeof(HMODULE);

	if (EnumProcessModules(process, modules, bytesRequired, &bytesRequired))
	{
		for (DWORD i = 0; i < moduleCount; i++) {
			HMODULE module = modules[i];

			char _baseName[512];

			GetModuleBaseNameA(process, module, _baseName, 512);

			if (strcmp(_baseName, dllName) == 0) {
				MODULEINFO info = { 0 };

				BOOL good = GetModuleInformation(process, module, &info, sizeof(MODULEINFO));

				if (!good) {
					DWORD lastError = GetLastError();
					CloseHandle(process);
					free(modules);

					return 0;
				}

				if (mdl != 0) {
					mdl->base = (DWORD)info.lpBaseOfDll;
					mdl->size = (DWORD)info.SizeOfImage;
				}

				addr = (DWORD)info.lpBaseOfDll;
				break;
			}
		}
	}

	free(modules);

	return addr;
}