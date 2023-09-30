#include "ntdll.h"
#include "hooks.h"
#include "defines.h"
#pragma comment(linker,"/BASE:0x10000000")

NTSTATUS wow64logInitStatus = STATUS_NOT_IMPLEMENTED;

extern "C"
{
	_declspec(dllexport) NTSTATUS Wow64LogInitialize()
	{
		return wow64logInitStatus; // STATUS_NOT_IMPLEMENT will trigger a dll unload. STATUS_SUCCESS will let our dll stay loaded.
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

	// Stack failures? nahhh we don't have these here.
	void __chkstk(size_t size)
	{
		return;
	}
}

bool CheckIfWantedProcess(HANDLE ntdllHandle)
{
	PPEB peb = NtCurrentPeb();

	wchar_t* image_file_name;
	image_file_name = wcsrchr_c(peb->ProcessParameters->ImagePathName.Buffer, L'\\') + 1; // Get last \ in string + 1 to skip it.

	if (wcscmp(image_file_name, L"Loader.exe") == NULL)
		return true;

	return false;
}

bool InitializeMisc(HANDLE* ntdllHandle)
{
	UNICODE_STRING ntdll_path;
	RtlInitUnicodeString(&ntdll_path, (PWSTR)L"ntdll.dll");

	if (!NT_SUCCESS(LdrGetDllHandle(NULL, NULL, &ntdll_path, ntdllHandle)))
		return false;

	if (ntdllHandle == INVALID_HANDLE_VALUE)
		return false;

	ANSI_STRING snwprintf_ansi;
	RtlInitAnsiString(&snwprintf_ansi, (PSTR)"_snwprintf");

	if (!NT_SUCCESS(LdrGetProcedureAddress(ntdllHandle, &snwprintf_ansi, NULL, (PVOID*)&snwprintf_c)))
		return false;

	ANSI_STRING wcsrchr_ansi;
	RtlInitAnsiString(&wcsrchr_ansi, (PSTR)"wcsrchr");
	_wcsrchr wcsrchr;

	if (!NT_SUCCESS(LdrGetProcedureAddress(ntdllHandle, &wcsrchr_ansi, NULL, (PVOID*)&wcsrchr_c)))
		return false;

	return true;
}

__declspec(noinline) /* Prevent inline for easier debugging*/
bool OnProcessAttach(HMODULE module)
{
	HANDLE ntdllHandle = INVALID_HANDLE_VALUE;

	if (!InitializeMisc(&ntdllHandle))
		return false;

	if (!CheckIfWantedProcess(ntdllHandle))
		return false;

	// If everything succeeded make sure we can't get unloaded in any way.
	LdrAddRefDll(LDR_ADDREF_DLL_PIN, module);

	Hooks::EnableLogging();
	Hooks::EnableHooking();

	// Tell wow64.dll Wow64LogInitialize "initialized" successfully.
	wow64logInitStatus = STATUS_SUCCESS;

	return true;
}

__declspec(noinline) // Prevent inline for easier debugging
bool OnProcessDetach(HMODULE module)
{
	Hooks::DisableHooking();
	Hooks::DisableLogging();
	return true;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		return OnProcessAttach(module);
	case DLL_PROCESS_DETACH:
		return OnProcessDetach(module);
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	default:
		break;
	}

	return TRUE;
}