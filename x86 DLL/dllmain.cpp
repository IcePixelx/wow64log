#include "../Wow64Log/ntdll.h"

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
//	PVOID* ntdll_handle = nullptr;

//	UNICODE_STRING ntdll_path;
//	RtlInitUnicodeString(&ntdll_path, (PWSTR)L"ntdll.dll"); // Init new unicode string for ntdll.dll.

//	NTSTATUS wtf = LdrGetDllHandle(NULL, NULL, &ntdll_path, ntdll_handle); // Get ntdll handle.

	SIZE_T allocation_size = 5;
	PVOID pointer_reference = nullptr;


	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		NtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pointer_reference, NULL, &allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	default:
		break;
	}

	return TRUE;
}

