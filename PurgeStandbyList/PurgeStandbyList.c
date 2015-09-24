/* PurgeStandbyList: purges the "standby list" (operating system caches). */

#include <Windows.h>
#include <stdio.h>

typedef enum
{
	SystemMemoryListInformation = 0x50,
} SYSTEM_INFORMATION_CLASS;

typedef enum
{
	MemoryPurgeStandbyList = 4,
} SYSTEM_MEMORY_LIST_COMMAND;

static void printerr(const WCHAR *message, HMODULE hModule, DWORD error_code)
{
	DWORD flags = 0;
	WCHAR *sysmsg;

	if (hModule)
		flags |= FORMAT_MESSAGE_FROM_HMODULE;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			flags,
		hModule,
		error_code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&sysmsg,
		0,
		NULL);

	fwprintf(stderr, L"%s: %s\n", message, sysmsg);

	LocalFree(sysmsg);
}

#define FAIL_HMODULE(msg, module, code) \
	do { printerr(msg, module, code); ret = 1; goto done; } while(0)
#define FAIL(msg) FAIL_HMODULE(msg, NULL, GetLastError())

int main(int argc, char **argv)
{
	NTSTATUS (NTAPI *NtSetSystemInformation)(
		SYSTEM_INFORMATION_CLASS, PVOID, DWORD);
	HMODULE hNt = NULL;
	HANDLE hToken = NULL;
	NTSTATUS result;
	DWORD memory_argument = MemoryPurgeStandbyList;
	LUID lPriv;
	TOKEN_PRIVILEGES tNewState = { 0 };
	int ret = 0;

	hNt = LoadLibrary(L"ntdll.dll");

	if ((NtSetSystemInformation =
			(NTSTATUS (NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, DWORD))
			GetProcAddress(hNt, "NtSetSystemInformation")) == NULL)
		FAIL(L"Failed to load NtSetSystemInformation");

	if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		FAIL(L"Failed to adjust process privileges");

	if (!LookupPrivilegeValue(NULL, SE_PROF_SINGLE_PROCESS_NAME, &lPriv))
		FAIL(L"Failed to lookup profiling privilege");

	tNewState.PrivilegeCount = 1;
	tNewState.Privileges[0].Luid = lPriv;
	tNewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(
			hToken, 0, &tNewState, sizeof(tNewState), NULL, 0))
		FAIL(L"Failed to adjust token privileges");

	if ((result = NtSetSystemInformation(
			SystemMemoryListInformation, &memory_argument, sizeof(int))) != 0)
		FAIL_HMODULE(L"Failed to purge standby list", hNt, result);

done:
	CloseHandle(hToken);
	FreeLibrary(hNt);
	return ret;
}
