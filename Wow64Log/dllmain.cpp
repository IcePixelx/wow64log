#include "ntdll.h"
#include "hooks.h"

#pragma comment(linker,"/BASE:0x10000000")

using _wcsrchr = wchar_t* (__cdecl*)(const wchar_t* Str, wchar_t Ch);

extern "C"
{
	_declspec(dllexport) NTSTATUS Wow64LogInitialize() // wow64.dll calls this so we do our setup here to check if the process is our wanted process.
	{
		UNICODE_STRING ntdll_path;
		RtlInitUnicodeString(&ntdll_path, (PWSTR)L"ntdll.dll"); // Init new unicode string for ntdll.dll.

		HANDLE ntdll_handle;
		LdrGetDllHandle(NULL, 0, &ntdll_path, &ntdll_handle); // Get ntdll handle.

		ANSI_STRING wcsrchr_ansi;
		RtlInitAnsiString(&wcsrchr_ansi, (PSTR)"wcsrchr"); // Init new unicode string for wcsrchr function.
		_wcsrchr wcsrchr;

		LdrGetProcedureAddress(ntdll_handle, &wcsrchr_ansi, NULL, (PVOID*)&wcsrchr); // Get wcsrchr function from ntdll.dll.

		PPEB peb = NtCurrentPeb(); // Get PEB

		wchar_t* image_file_name;
		image_file_name = wcsrchr(peb->ProcessParameters->ImagePathName.Buffer, L'\\') + 1; // Get last \ in string + 1 to skip it.

		if (wcscmp(image_file_name, L"IcyCore-Executeable.exe") == NULL) // Our wanted executeable?
		{
			Hooks::EnableHooking(); // Hook all the functions we need!
			return STATUS_SUCCESS; // Keep us running.
		}
		else
		{
			return STATUS_NOT_IMPLEMENTED; // Let wow64.dll set all imported functions to nullptr. LdrUnloadDLL won't unload us I don't get why but dll will be harmless if we return this.
		}
	}

	_declspec(dllexport) NTSTATUS Wow64LogSystemService(void* unk1)
	{
		return STATUS_SUCCESS;
	}

	_declspec(dllexport) NTSTATUS Wow64LogMessageArgList(unsigned long type, char* format_string, void* arguments)
	{
		return STATUS_SUCCESS;
	}

	_declspec(dllexport) NTSTATUS Wow64LogTerminate()
	{
		return STATUS_SUCCESS;
	}
}

void OnProcessAttach(HMODULE module)
{
	LdrAddRefDll(LDR_ADDREF_DLL_PIN, module); // Add dll reference so we can unload it 

	// TODO: Unlink module from peb.
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		OnProcessAttach(module);
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