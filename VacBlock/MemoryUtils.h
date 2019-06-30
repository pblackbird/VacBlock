#include <Windows.h>
#include <Psapi.h>

typedef struct {
	UINT64 size;
	UINT64 base;
} Module;


DWORD GetModule(CONST CHAR* dllName, Module* mdl);
DWORD SearchForSignature(DWORD start, unsigned char* pattern, SIZE_T sizeOfPattern, SIZE_T size);