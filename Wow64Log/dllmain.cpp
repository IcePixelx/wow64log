#include "ntdll.h"
#include "hooks.h"
#include "defines.h"
#pragma comment(linker,"/BASE:0x10000000")

NTSTATUS init_status = STATUS_NOT_IMPLEMENTED;

extern "C"
{
	_declspec(dllexport) NTSTATUS Wow64LogInitialize()
	{
		return init_status; // STATUS_NOT_IMPLEMENT will trigger a dll unload. STATUS_SUCCESS will let our dll stay loaded.
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

/*	UNICODE_STRING text_file;
	OBJECT_ATTRIBUTES object_attributes;
	IO_STATUS_BLOCK io_status;
	HANDLE out;

	const wchar_t* test_path = L"C:\\Users\\Public\\testfile.txt"; // file path.

	if (!RtlDosPathNameToNtPathName_U(test_path, &text_file, NULL, NULL)) // Convert common DOS path to NT path.
		return false;

	memset(&io_status, 0, sizeof(io_status));
	memset(&object_attributes, 0, sizeof(object_attributes));
	object_attributes.Length = sizeof(object_attributes);
	object_attributes.Attributes = OBJ_CASE_INSENSITIVE;
	object_attributes.ObjectName = &text_file;

	NTSTATUS status = NtCreateFile(&out, FILE_GENERIC_WRITE, &object_attributes, &io_status, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	_snwprintf snwprintf = nullptr;

	ANSI_STRING RoutineName;
	RtlInitAnsiString(&RoutineName, (PSTR)"_snwprintf");
	LdrGetProcedureAddress(ntdll_handle, &RoutineName, 0, (PVOID*)&snwprintf);

	WCHAR Buffer[1024];
	snwprintf(Buffer, RTL_NUMBER_OF(Buffer), L"Test2\n");

	PPEB peb = NtCurrentPeb(); // Get PEB

	status = NtWriteFile(out, NULL, NULL, NULL, &io_status, Buffer, (int)wcslen(Buffer) * 2, NULL, NULL);

	NtClose(out);*/

bool CheckIfWantedProcess(HANDLE ntdll_handle)
{
	ANSI_STRING wcsrchr_ansi;
	RtlInitAnsiString(&wcsrchr_ansi, (PSTR)"wcsrchr"); // Init new unicode string for wcsrchr function.
	_wcsrchr wcsrchr; // Function template for wcsrchr.

	if (!NT_SUCCESS(LdrGetProcedureAddress(ntdll_handle, &wcsrchr_ansi, NULL, (PVOID*)&wcsrchr))) // Get wcsrchr function from ntdll.dll.
		return false; // return if it isnt STATUS_SUCCESS.

	PPEB peb = NtCurrentPeb(); // Get PEB

	if (!peb) // PEB valid?
		return false;

	wchar_t* image_file_name;
	image_file_name = wcsrchr(peb->ProcessParameters->ImagePathName.Buffer, L'\\') + 1; // Get last \ in string + 1 to skip it.

	if (wcscmp(image_file_name, L"IcyCore-Executeable.exe") == NULL) // Our wanted executeable?
		return true;

	return false; // Not our wanted process, return false.
}

bool ExecuteX86Process(HANDLE ntdll_handle)
{
	UNICODE_STRING nt_path_name; // Initialize new NT path name.
	PRTL_USER_PROCESS_PARAMETERS user_process_parameters; // Initialize user process parameters.
	RTL_USER_PROCESS_INFORMATION process_info; // Initialize process_info.

	const wchar_t* executable_path = L"C:\\injector.exe"; // X86 executeable path.

	if (!RtlDosPathNameToNtPathName_U(executable_path, &nt_path_name, NULL, NULL)) // Convert common DOS path to NT path.
		return false;

	if (!NT_SUCCESS(RtlCreateProcessParameters(&user_process_parameters, &nt_path_name, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))) // Create process parameters.
		return false;

	if (!NT_SUCCESS(RtlCreateUserProcess(&nt_path_name, OBJ_CASE_INSENSITIVE, user_process_parameters, NULL, NULL, NULL, FALSE, NULL, NULL, &process_info))) // Create our x86 executeable.
		return false;

	NtResumeThread(process_info.ThreadHandle, NULL);  // RtlCreateUserProcess launched our main thread as suspended so lets resume it.

	NtWaitForSingleObject(process_info.ProcessHandle, FALSE, NULL); // Wait for the x86 executeable to finish executing.

	NtClose(process_info.ThreadHandle); // Close thread handle.
	NtClose(process_info.ProcessHandle); // Close process handle.

	return true;
}

bool InitializeHandles(HANDLE* ntdll_handle)
{
	UNICODE_STRING ntdll_path;
	RtlInitUnicodeString(&ntdll_path, (PWSTR)L"ntdll.dll"); // Init new unicode string for ntdll.dll.

	if (!NT_SUCCESS(LdrGetDllHandle(NULL, NULL, &ntdll_path, ntdll_handle))) // Get ntdll handle.
		return false;

	if (ntdll_handle == INVALID_HANDLE_VALUE) // Is ntdll handle valid?
		return false;

	return true;
}

__declspec(noinline) /* Prevent inline for easier debugging*/
bool OnProcessAttach(HMODULE module)
{
	HANDLE ntdll_handle = INVALID_HANDLE_VALUE; // Initialize ntdll handle.

	if (!InitializeHandles(&ntdll_handle)) // Do handle initializing here.
		return false;

	if (!CheckIfWantedProcess(ntdll_handle)) // Is our wanted process?
		return false;

//	if (!ExecuteX86Process(ntdll_handle)) // Launch our 32-bit process.
//		return false;

	LdrAddRefDll(LDR_ADDREF_DLL_PIN, module); // If everything succeeded make sure we can't get unloaded in any way.

	Hooks::EnableHooking(); // Hook all the functions we need!
	Hooks::InitializeLogging(ntdll_handle);

	init_status = STATUS_SUCCESS; // Tell wow64.dll Wow64LogInitialize "initialized" successfully.

	return true;
}

__declspec(noinline) /* Prevent inline for easier debugging*/
bool OnProcessDetach(HMODULE module)
{
	Hooks::DisableHooking(); // Incase we somehow get unloaded prevent a crash.
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