#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#define IS_HANDLE_INVALID(handle) !handle || handle == INVALID_HANDLE_VALUE

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef NTSTATUS(NTAPI* fnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI* fnLdrLoadDll)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);

struct THREAD_DATA
{
	fnRtlInitUnicodeString fn_rtl_init_unicode_string; // Pointer to RtlInitUnicodeString
	fnLdrLoadDll fn_ldr_load_dll; // Pointer to LdrLoadDll
	UNICODE_STRING unicode_string; // Will hold our dll name.
	WCHAR dll_name[280]; // Dll name.
	PWCHAR dll_path; // Dll path.
	ULONG flags; // Flags if needed.
	HANDLE module_handle; // Final module handle.
};

HANDLE WINAPI LoadLibraryThread(THREAD_DATA* data) // Our "LoadLibrary" replacement.
{
	data->fn_rtl_init_unicode_string(&data->unicode_string, data->dll_name); // Call RtlUnicodeString to initialize the unicode string.
	data->fn_ldr_load_dll(data->dll_path, data->flags, &data->unicode_string, &data->module_handle); // Call LdrLoadDll to load our dll.
	return data->module_handle; // Return Module handle.
}

DWORD WINAPI LoadLibraryThreadEnd() // Needed to calculate code delta.
{
	return 0;
}

DWORD GetProcessID(std::string process_name)
{
	DWORD pid = -1;

	try
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL); // Open tool snapshot.
		if (IS_HANDLE_INVALID(snapshot)) // Snapshot valid?
			throw std::exception("Couldn't get process snapshot");

		if (WaitForSingleObject(snapshot, NULL) == WAIT_TIMEOUT) // Its taking too long to open the snapshot?
			throw std::exception("Couldn't get process snapshot");

		PROCESSENTRY32 process_entry; // Initialize PROCESSENTRY32.
		process_entry.dwSize = sizeof(PROCESSENTRY32); // Set size to struct.

		if (!Process32First(snapshot, &process_entry)) // Get process list.
		{
			CloseHandle(snapshot);
			throw std::exception("Couldn't get process list.");
		}

		do
		{
			if (strcmp(process_entry.szExeFile, process_name.c_str()) == NULL) // Check if current process list entry equals our wanted process.
			{
				pid = process_entry.th32ProcessID; // Get process id.
				break;
			}

		} while (Process32Next(snapshot, &process_entry));

		CloseHandle(snapshot); // Close opened handles.

		if (pid == -1) // Is pid actually valid?
			throw std::exception("Couldn't get pid.");

		return pid;
	}
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
		system("pause");
		return 0;
	}
}

int main()
{
	std::cout << "wow64log injection." << std::endl;
	const std::string process_name = "IcyCore-Executeable.exe";

	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);

	const std::size_t position_of_last_directory_location = std::string(buffer).find_last_of("\\/");
	std::string executable_path = std::string(buffer).substr(0, position_of_last_directory_location);

	try
	{
		DWORD pid = GetProcessID(process_name); // Get process id for wanted process.
		if (pid == -1) // Did the function fail?
			throw std::exception("Couldn't get pid.");

		HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); // Open the process via process id with full access.
		if (IS_HANDLE_INVALID(process_handle)) // Is the process handle valid?
			throw std::exception("Couldn't get process handle.");

		HMODULE ntdll_module = GetModuleHandleA("ntdll.dll"); // Grab ntdll module.
		if (!ntdll_module)
		{
			CloseHandle(process_handle);
			throw std::exception("Couldn't get ntdll.dll module.");
		}

		THREAD_DATA data; // Initialize struct.

		FARPROC rtl_init_unicode_string = GetProcAddress(ntdll_module, "RtlInitUnicodeString");
		if (!rtl_init_unicode_string)
		{
			CloseHandle(process_handle);
			throw std::exception("Couldn't get RtlInitUnicodeString from ntdll.");
		}

		FARPROC ldr_load_dll = GetProcAddress(ntdll_module, "LdrLoadDll");
		if (!ldr_load_dll)
		{
			CloseHandle(process_handle);
			throw std::exception("Couldn't get LdrLoadDll from ntdll.");
		}


		/* Fill struct with data. */
		data.fn_rtl_init_unicode_string = reinterpret_cast<fnRtlInitUnicodeString>(rtl_init_unicode_string); // Cast it to the function prototype.
		data.fn_ldr_load_dll = reinterpret_cast<fnLdrLoadDll>(ldr_load_dll); // Cast it to the function prototype.
		memcpy(data.dll_name, L"C:\\x86 DLL.dll", 15 * sizeof(WCHAR)); // Static because I was lazy.
		data.flags = NULL; // Initialize flags.
		data.module_handle = INVALID_HANDLE_VALUE; // Initialize handle.

		DWORD size_of_code = (DWORD)LoadLibraryThreadEnd - (DWORD)LoadLibraryThread; // Get a rough delta of our code size.

		LPVOID allocated_thread_data = VirtualAllocEx(process_handle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocate new code section in target process for our thread data.
		if (!allocated_thread_data)
		{
			throw std::exception("Couldn't allocate code section for thread data.");
		}

		BOOL write_ok = WriteProcessMemory(process_handle, allocated_thread_data, &data, sizeof(data), NULL); // Write thread data to allocated code section in target process.
		if (!write_ok)
		{
			throw std::exception("Couldn't write thread data to allocated code section in target process.");
		}

		LPVOID allocated_function = VirtualAllocEx(process_handle, NULL, size_of_code, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate new code section for our start routine function.
		if (!allocated_function)
		{
			throw std::exception("Couldn't allocate section for start routine function.");
		}

		write_ok = WriteProcessMemory(process_handle, allocated_function, (PVOID)LoadLibraryThread, size_of_code, NULL); // Write start routine function to allocated code section in target process.
		if (!write_ok)
		{
			throw std::exception("Couldn't write start routine function to allocated code section in target process.");
		}

		// Create new thread in remote process. Calling our allocated code section in the process.
		HANDLE remote_thread = CreateRemoteThread(process_handle, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(allocated_function), allocated_thread_data, NULL, nullptr);
		if (IS_HANDLE_INVALID(remote_thread))
		{
			CloseHandle(process_handle);
			throw std::exception("Couldn't create remotethread.");
		}

		if (WaitForSingleObject(remote_thread, 1000) == WAIT_OBJECT_0) // Wait for remote thread to finish.
		{
			DWORD exitCode = NULL;
			if (!GetExitCodeThread(remote_thread, &exitCode)) // Get exit code.
			{
				CloseHandle(process_handle);
				CloseHandle(remote_thread);
				throw std::exception("Couldn't get exitcode for remotethread.");
			}
		}

		CloseHandle(remote_thread); // Close remote thread handle.
		CloseHandle(process_handle); // Close process handle.

		return 0;
	}
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
		system("pause");
		return 0;
	}

	return 0;
}