#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

DWORD FindProcess(CONST CHAR* pName) {
	HANDLE helper = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	if (helper == INVALID_HANDLE_VALUE) {
		return 0;
	}

	DWORD pid = 0;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);

	if (!Process32First(helper, &entry)) {
		return 0;
	}

	while (Process32Next(helper, &entry)) {
		if (strcmp(entry.szExeFile, pName) == 0) {
			pid = entry.th32ProcessID;
			break;
		}
	}

	CloseHandle(helper);

	return pid;
}

int LoadPrivilege(void) {
	HANDLE hToken;
	LUID Value;
	TOKEN_PRIVILEGES tp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return(GetLastError());
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Value))
		return(GetLastError());
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Value;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
		return(GetLastError());
	CloseHandle(hToken);
	return 1;
}

void SetConsoleColour(WORD* Attributes, DWORD Colour)
{
	CONSOLE_SCREEN_BUFFER_INFO Info;
	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(hStdout, &Info);
	*Attributes = Info.wAttributes;
	SetConsoleTextAttribute(hStdout, Colour);
}

bool Inject() 
{
	DWORD pid = FindProcess("SteamService.exe");

	if(!pid) {
		return false;
	}

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (process == INVALID_HANDLE_VALUE) {
		return false;
	}

	char fullFilename[MAX_PATH];
	const char* filename = "VacBlock.dll";
	GetFullPathName(filename, MAX_PATH, fullFilename, nullptr);

	SIZE_T _fixed = strlen(fullFilename) + 1;

	LPVOID dllNameAllocated = VirtualAllocEx(
		process,
		NULL,
		_fixed,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	SIZE_T written;
	BOOL _wr_res = WriteProcessMemory(process, dllNameAllocated, fullFilename, _fixed, &written);

	if (!_wr_res) {
		return false;
	}

	LPVOID _llib = GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");

	HANDLE _thread = CreateRemoteThread(
		process,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)_llib,
		dllNameAllocated,
		0,
		NULL);

	CloseHandle(process);

	return true;
}

void ResetConsoleColour(WORD Attributes)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), Attributes);
}

int main() {

	WORD Attributes = 0;

	printf("Steam AntiVAC v0.2 by Kirie\n");

	Sleep(1000);

	SetConsoleColour(&Attributes, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	printf("[*] ");
	ResetConsoleColour(Attributes);
	printf("Acquiring SE_DEBUG_NAME ...\n");

	if(!LoadPrivilege()) {
		SetConsoleColour(&Attributes, FOREGROUND_INTENSITY | FOREGROUND_RED);
		printf("[!] ");
		ResetConsoleColour(Attributes);

		printf("Error acquiring SE_DEBUG_NAME: 0x%p\n", GetLastError());

		system("pause");

		return 1;
	}

	SetConsoleColour(&Attributes, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	printf("[*] ");
	ResetConsoleColour(Attributes);
	printf("Injecting DLL ...\n");

	bool injected = Inject();

	if(!injected) {
		SetConsoleColour(&Attributes, FOREGROUND_INTENSITY | FOREGROUND_RED);
		printf("[!] ");
		ResetConsoleColour(Attributes);

		printf("Inject error: 0x%p\n", GetLastError());

		system("pause");

		return 1;
	}

	SetConsoleColour(&Attributes, FOREGROUND_INTENSITY | FOREGROUND_BLUE);
	printf("[*] ");
	ResetConsoleColour(Attributes);
	printf("Injected!\n");

	printf("\n!!! NOW VAC IS FROZEN, YOU CAN INJECT DETECTED HACKS !!!\n\n");

	system("pause");

	return 0;
}