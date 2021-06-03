#include "../Wow64Log/ntdll.h"

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
//	PVOID* ntdll_handle = nullptr;

//	UNICODE_STRING ntdll_path;
//	RtlInitUnicodeString(&ntdll_path, (PWSTR)L"ntdll.dll"); // Init new unicode string for ntdll.dll.

//	NTSTATUS wtf = LdrGetDllHandle(NULL, NULL, &ntdll_path, ntdll_handle); // Get ntdll handle.

	SIZE_T allocation_size = 5;
	PVOID pointer_reference = (PVOID)123564;
	PVOID yes = nullptr;
	SIZE_T test = 0;


	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		NtReadVirtualMemory(reinterpret_cast<HANDLE>(-1), pointer_reference, yes, 4, &test);
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

