#include "hooks.h"
#include "ntdll.h"
#include <detours.h>
#include "defines.h"

Logging* thread_log;
_snwprintf snwprintf = nullptr;

namespace Hooks
{
	namespace
	{
		Logging* nt_allocate_virtual_memory_log;
		Logging* nt_free_virtual_memory_log;
		Logging* nt_protect_virtual_memory_log;
		Logging* nt_read_virtual_memory_log;
		Logging* nt_query_virtual_memory_log;
		Logging* nt_write_virtual_memory_log;
	//	int i = 0;
	}

	// Original functions.
	decltype(NtAllocateVirtualMemory)* orig_nt_allocate_virtual_memory = nullptr;
	decltype(NtProtectVirtualMemory)* orig_nt_protect_virtual_memory = nullptr;
	decltype(NtReadVirtualMemory)* orig_nt_read_virtual_memory = nullptr;
	decltype(NtWriteVirtualMemory)* orig_nt_write_virtual_memory = nullptr;
	decltype(NtFreeVirtualMemory)* orig_nt_free_virtual_memory = nullptr;
	decltype(NtQueryVirtualMemory)* orig_nt_query_virtual_memory = nullptr;

#pragma optimize("", off)

	void __stdcall ThreadProc()
	{
		PEB32* peb32 = GetPEB32(); // Get PEB32.

		while (true) // Keep thread alive.
		{
			_PEB_LDR_DATA32* peb_ldr_data = (_PEB_LDR_DATA32*)peb32->Ldr; // Get PEB loader data.
			if (!peb_ldr_data) // Is peb_ldr_data valid yet?
				continue;

			LIST_ENTRY32* memory_order_module_list = &peb_ldr_data->InMemoryOrderModuleList; // Get memory module list.
			LIST_ENTRY32* memory_order_module_list_head = memory_order_module_list; // Get start of memory module list.

			PVOID ntdll_base = nullptr; // Init ptr void variable for ntdll_base.

			do
			{
				PLDR_DATA_TABLE_ENTRY32 pldr_data_table_entry = CONTAINING_RECORD(memory_order_module_list, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks); // Does current entry contain a record?

				if (pldr_data_table_entry) // Is data table entry valid?
				{
					if (pldr_data_table_entry->SizeOfImage == 0x19A000) // Check for ntdll size of image.
					{
						ntdll_base = (PVOID)pldr_data_table_entry->DllBase; // Grab ntdll 32-bit base address.

						WCHAR log_buffer[100]; // Initialize log buffer.
						snwprintf(log_buffer, RTL_NUMBER_OF(log_buffer), L"0x%X\n", ntdll_base);

						if (thread_log) // Valid ptr?
							thread_log->WriteToFile(log_buffer, (int)wcslen(log_buffer) * sizeof(wchar_t)); // Write log buffer to our file.

						break; // found ntdll lets break outta here.
					}
				}

				memory_order_module_list = (LIST_ENTRY32*)memory_order_module_list->Flink; // Next entry.

			} while (memory_order_module_list_head != (LIST_ENTRY32*)memory_order_module_list->Flink); // Check if entries are still valid

			break; // Break out of loop.
		}

		NtClose(thread_log->GetFileHandle()); // Close logging file at end of thread.
	}

#pragma optimize("", on)

	PEB32* GetPEB32()
	{
		PVOID teb32 = (char*)NtCurrentTeb() + 0x2000; // Offset from TEB64 to TEB32.
		return (PEB32*)((_TEB32*)teb32)->ProcessEnvironmentBlock; // Grab PEB32 from TEB32.
	}

	// Start hooks.
	void EnableHooking()
	{
		DetourTransactionBegin();

		Hooks::orig_nt_allocate_virtual_memory = NtAllocateVirtualMemory;
		Hooks::orig_nt_protect_virtual_memory = NtProtectVirtualMemory;
		Hooks::orig_nt_read_virtual_memory = NtReadVirtualMemory;
		Hooks::orig_nt_write_virtual_memory = NtWriteVirtualMemory;
		Hooks::orig_nt_free_virtual_memory = NtFreeVirtualMemory;
		Hooks::orig_nt_query_virtual_memory = NtQueryVirtualMemory;

		DetourAttach((PVOID*)&Hooks::orig_nt_allocate_virtual_memory, Hooks::hkNtAllocateVirtualMemory);
		DetourAttach((PVOID*)&Hooks::orig_nt_free_virtual_memory, Hooks::hkNtFreeVirtualMemory);
		DetourAttach((PVOID*)&Hooks::orig_nt_protect_virtual_memory, Hooks::hkNtProtectVirtualMemory);
		DetourAttach((PVOID*)&Hooks::orig_nt_read_virtual_memory, Hooks::hkNtReadVirtualMemory);
		DetourAttach((PVOID*)&Hooks::orig_nt_write_virtual_memory, Hooks::hkNtWriteVirtualMemory);
		DetourAttach((PVOID*)&Hooks::orig_nt_query_virtual_memory, Hooks::hkNtQueryVirtualMemory);

		DetourTransactionCommit();
	}

	// Stop hooks.
	void DisableHooking()
	{
		DetourTransactionBegin();

		DetourDetach((PVOID*)&Hooks::orig_nt_allocate_virtual_memory, Hooks::hkNtAllocateVirtualMemory);
		DetourDetach((PVOID*)&Hooks::orig_nt_free_virtual_memory, Hooks::hkNtFreeVirtualMemory);
		DetourDetach((PVOID*)&Hooks::orig_nt_protect_virtual_memory, Hooks::hkNtProtectVirtualMemory);
		DetourDetach((PVOID*)&Hooks::orig_nt_read_virtual_memory, Hooks::hkNtReadVirtualMemory);
		DetourDetach((PVOID*)&Hooks::orig_nt_write_virtual_memory, Hooks::hkNtWriteVirtualMemory);
		DetourDetach((PVOID*)&Hooks::orig_nt_query_virtual_memory, Hooks::hkNtQueryVirtualMemory);

		DetourTransactionCommit();
	}

	NTSTATUS InitializeLogging(HANDLE ntdll_handle)
	{
		NTSTATUS result = STATUS_WAIT_0; 

		ANSI_STRING snwprintf_ansi; // Initialize new ansi string for swnprintf.
		RtlInitAnsiString(&snwprintf_ansi, (PSTR)"_snwprintf"); // Fill ANSI_STRING struct with a string.

		result = LdrGetProcedureAddress(ntdll_handle, &snwprintf_ansi, NULL, (PVOID*)&snwprintf); // Get export for swnprintf.
		if (!NT_SUCCESS(result)) // Did LdrGetProcedureAddress succeed?
			return result;

		/*
		   We are initializing class instances here.
		   Please keep in mind if you set a folder path that it isn't protected by UAC. (User Account Control or in common terms the Admin Prompt)
		   Otherwise it will fail or you need to launch the programm as admin.
		   We will just leak the heap because the handles only will be closed on program close.
		*/

		thread_log = (Logging*)RtlAllocateHeap(RtlProcessHeap(), NULL, sizeof(Logging)); // Allocate heap for class instance.
		thread_log->Setup(L"C:\\Users\\Public\\ThreadLog.txt"); // Create Logging class instance.
		result = thread_log->CreateFileHandle(FILE_GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT); // Create file handle.
		if (!NT_SUCCESS(result)) // Did CreateFileHandle succeed?
			return result;

		nt_allocate_virtual_memory_log = (Logging*)RtlAllocateHeap(RtlProcessHeap(), NULL, sizeof(Logging)); // Allocate heap for class instance.
		nt_allocate_virtual_memory_log->Setup(L"C:\\Users\\Public\\NtAllocateVirtualMemoryLog.txt"); // Create Logging class instance.
		result = nt_allocate_virtual_memory_log->CreateFileHandle(FILE_GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT); // Create file handle.
		if (!NT_SUCCESS(result)) // Did CreateFileHandle succeed?
			return result;

		nt_protect_virtual_memory_log = (Logging*)RtlAllocateHeap(RtlProcessHeap(), NULL, sizeof(Logging)); // Allocate heap for class instance.
		nt_protect_virtual_memory_log->Setup(L"C:\\Users\\Public\\NtProtectVirtualMemoryLog.txt"); // Create Logging class instance.
		result = nt_protect_virtual_memory_log->CreateFileHandle(FILE_GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT); // Create file handle.
		if (!NT_SUCCESS(result)) // Did CreateFileHandle succeed?
			return result;

		nt_read_virtual_memory_log = (Logging*)RtlAllocateHeap(RtlProcessHeap(), NULL, sizeof(Logging)); // Allocate heap for class instance.
		nt_read_virtual_memory_log->Setup(L"C:\\Users\\Public\\NtReadVirtualMemory.txt"); // Create Logging class instance.
		result = nt_read_virtual_memory_log->CreateFileHandle(FILE_GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT); // Create file handle.
		if (!NT_SUCCESS(result)) // Did CreateFileHandle succeed?
			return result;

		nt_write_virtual_memory_log = (Logging*)RtlAllocateHeap(RtlProcessHeap(), NULL, sizeof(Logging)); // Allocate heap for class instance.
		nt_write_virtual_memory_log->Setup(L"C:\\Users\\Public\\NtWriteVirtualMemory.txt"); // Create Logging class instance.
		result = nt_write_virtual_memory_log->CreateFileHandle(FILE_GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT); // Create file handle.
		if (!NT_SUCCESS(result)) // Did CreateFileHandle succeed?
			return result;

		nt_free_virtual_memory_log = (Logging*)RtlAllocateHeap(RtlProcessHeap(), NULL, sizeof(Logging)); // Allocate heap for class instance.
		nt_free_virtual_memory_log->Setup(L"C:\\Users\\Public\\NtFreeVirtualMemory.txt"); // Create Logging class instance.
		result = nt_free_virtual_memory_log->CreateFileHandle(FILE_GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT); // Create file handle.
		if (!NT_SUCCESS(result)) // Did CreateFileHandle succeed?
			return result;

		nt_query_virtual_memory_log = (Logging*)RtlAllocateHeap(RtlProcessHeap(), NULL, sizeof(Logging)); // Allocate heap for class instance.
		nt_query_virtual_memory_log->Setup(L"C:\\Users\\Public\\NtQueryVirtualMemory.txt"); // Create Logging class instance.
		result = nt_query_virtual_memory_log->CreateFileHandle(FILE_GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT); // Create file handle.
		if (!NT_SUCCESS(result)) // Did CreateFileHandle succeed?
			return result;

		/* PROCESS NEEDS TO BE ELEVEATED TO NTCREATETHREADEX WTF?*/
	//	HANDLE thread;
	//	NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)ThreadProc, NULL, FALSE, NULL, NULL, NULL, NULL);
	//	NtClose(thread);

		return STATUS_SUCCESS; 
	}

	// Hook functions.
	NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
	{
		SIZE_T region_size_before_call = *RegionSize; // Grab RegionSize before original modifies it.

		NTSTATUS result = Hooks::orig_nt_allocate_virtual_memory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect); // call original.

		if ((DWORD)*BaseAddress > 0x7FFFFFFF) // Dont fuck with this if its in 64bit address space some will still come through sadly..
			return result; // return original.

		ULONG query_info_returned_length; // Initialize return length variable.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, NULL, &query_info_returned_length); // Query size for the ProcessImageFileName.

		UNICODE_STRING* process_image_name = (UNICODE_STRING*)RtlAllocateHeap(RtlProcessHeap(), NULL, query_info_returned_length); // Allocate new heap for the size of the returned length.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, process_image_name, query_info_returned_length, &query_info_returned_length); // Now actually query the process image name.

		PPEB peb = NtCurrentPeb(); // Get PEB.
		PEB_LDR_DATA* peb_ldr_data = peb->Ldr; // Get peb loader data.

		LIST_ENTRY* memory_order_module_list = &peb_ldr_data->InMemoryOrderModuleList; // Get memory module list.
		LIST_ENTRY* memory_order_module_list_head = memory_order_module_list; // Get start of memory module list.

		WCHAR* module_name = NULL; // Future module_name.

		do
		{
			PLDR_DATA_TABLE_ENTRY pldr_data_table_entry = CONTAINING_RECORD(memory_order_module_list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks); // Does current entry contain a record?

			if (pldr_data_table_entry)
			{
				size_t size_of_image = pldr_data_table_entry->SizeOfImage; // Get size of dll image.
				if ((size_t)*BaseAddress - (size_t)pldr_data_table_entry->DllBase < size_of_image) // Check if our baseaddress is in bounds of current looped module.
				{
					module_name = pldr_data_table_entry->BaseDllName.Buffer; // Found our module.
					break; // Break since we found our module.
				}
			}

			memory_order_module_list = memory_order_module_list->Flink; // Next entry.

		} while (memory_order_module_list_head != memory_order_module_list->Flink); // Check if entries are still valid


		WCHAR log_buffer[1028]; // Initialize log buffer.

		// Fill log buffer with information of our hook.
		snwprintf(log_buffer, RTL_NUMBER_OF(log_buffer), L"NtAllocateVirtualMemory called for '%s' '%s'. BaseAddress: 0x%X, RegionSize: 0x%X, AllocationType: 0x%X, Protect: 0x%X, Result: 0x%X\n",
			process_image_name->Buffer, module_name, *BaseAddress, region_size_before_call, AllocationType, Protect, result);

		if (nt_allocate_virtual_memory_log) // Valid ptr?
			nt_allocate_virtual_memory_log->WriteToFile(log_buffer, (int)wcslen(log_buffer) * sizeof(wchar_t)); // Write log buffer to our file.

		RtlFreeHeap(RtlProcessHeap(), NULL, process_image_name); // Free the heap for process_image_name.

		return result; // return original.
	}

	NTSTATUS NTAPI hkNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
	{
		NTSTATUS result = orig_nt_free_virtual_memory(ProcessHandle, BaseAddress, RegionSize, FreeType); // call original.

		if ((DWORD)*BaseAddress > 0x7FFFFFFF) // Dont fuck with this if its in 64bit address space some will still come through sadly..
			return result; // return original.

		ULONG query_info_returned_length; // Initialize return length variable.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, NULL, &query_info_returned_length); // Query size for the ProcessImageFileName.

		UNICODE_STRING* process_image_name = (UNICODE_STRING*)RtlAllocateHeap(RtlProcessHeap(), NULL, query_info_returned_length); // Allocate new heap for the size of the returned length.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, process_image_name, query_info_returned_length, &query_info_returned_length); // Now actually query the process image name.

		WCHAR log_buffer[1028]; // Initialize log buffer.

		snwprintf(log_buffer, RTL_NUMBER_OF(log_buffer), L"NtFreeVirtualMemory called for '%s'. BaseAddress: 0x%X, RegionSize: 0x%X, FreeType: 0x%X, Result: 0x%X\n",
			process_image_name->Buffer, *BaseAddress, *RegionSize, FreeType, result);

		if (nt_free_virtual_memory_log) // Valid ptr?
			nt_free_virtual_memory_log->WriteToFile(log_buffer, (int)wcslen(log_buffer) * sizeof(wchar_t)); // Write log buffer to our file.

		RtlFreeHeap(RtlProcessHeap(), NULL, process_image_name); // Free the heap for process_image_name.

		return result;
	}

	NTSTATUS NTAPI hkNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
	{
		SIZE_T region_size_before_call = *RegionSize; // Grab RegionSize before original modifies it.

		NTSTATUS result = Hooks::orig_nt_protect_virtual_memory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect); // call original.

		if ((DWORD)*BaseAddress > 0x7FFFFFFF) // Dont fuck with this if its in 64bit address space some will still come through sadly..
			return result; // return original.

		ULONG query_info_returned_length; // Initialize return length variable.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, NULL, &query_info_returned_length); // Query size for the ProcessImageFileName.

		UNICODE_STRING* process_image_name = (UNICODE_STRING*)RtlAllocateHeap(RtlProcessHeap(), NULL, query_info_returned_length); // Allocate new heap for the size of the returned length.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, process_image_name, query_info_returned_length, &query_info_returned_length); // Now actually query the process image name.

		WCHAR log_buffer[1028]; // Initialize log buffer.

		snwprintf(log_buffer, RTL_NUMBER_OF(log_buffer), L"NtProtectVirtualMemory called for '%s'. BaseAddress: 0x%X, RegionSize: 0x%X, NewProtect: 0x%X, OldProtect: 0x%X, Result: 0x%X\n",
			process_image_name->Buffer, *BaseAddress, region_size_before_call, NewProtect, *OldProtect, result);

		if (nt_protect_virtual_memory_log) // Valid ptr?
			nt_protect_virtual_memory_log->WriteToFile(log_buffer, (int)wcslen(log_buffer) * sizeof(wchar_t)); // Write log buffer to our file.

		RtlFreeHeap(RtlProcessHeap(), NULL, process_image_name); // Free the heap for process_image_name.

		return result;
	}

	NTSTATUS NTAPI hkNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
	{
		NTSTATUS result = Hooks::orig_nt_read_virtual_memory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead); // call original.

		if ((DWORD)BaseAddress > 0x7FFFFFFF) // Dont fuck with this if its in 64bit address space some will still come through sadly..
			return result; // return original.

		ULONG query_info_returned_length; // Initialize return length variable.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, NULL, &query_info_returned_length); // Query size for the ProcessImageFileName.

		UNICODE_STRING* process_image_name = (UNICODE_STRING*)RtlAllocateHeap(RtlProcessHeap(), NULL, query_info_returned_length); // Allocate new heap for the size of the returned length.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, process_image_name, query_info_returned_length, &query_info_returned_length); // Now actually query the process image name.

		WCHAR log_buffer[1028]; // Initialize log buffer.

		snwprintf(log_buffer, RTL_NUMBER_OF(log_buffer), L"NtReadVirtualMemory called for '%s'. BaseAddress: 0x%X, Buffer: 0x%X, BufferSize: 0x%X, NumberOfBytesRead: 0x%X, Result: 0x%X\n",
			process_image_name->Buffer, BaseAddress, Buffer, BufferSize, *NumberOfBytesRead, result);

		if (nt_read_virtual_memory_log) // Valid ptr?
			nt_read_virtual_memory_log->WriteToFile(log_buffer, (int)wcslen(log_buffer) * sizeof(wchar_t)); // Write log buffer to our file.

		RtlFreeHeap(RtlProcessHeap(), NULL, process_image_name); // Free the heap for process_image_name.

		return result;
	}

	NTSTATUS NTAPI hkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
	{
		NTSTATUS result = Hooks::orig_nt_write_virtual_memory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead); // call original.

		if ((DWORD)BaseAddress > 0x7FFFFFFF) // Dont fuck with this if its in 64bit address space some will still come through sadly..
			return result; // return original.
		
		ULONG query_info_returned_length; // Initialize return length variable.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, NULL, &query_info_returned_length); // Query size for the ProcessImageFileName.

		UNICODE_STRING* process_image_name = (UNICODE_STRING*)RtlAllocateHeap(RtlProcessHeap(), NULL, query_info_returned_length); // Allocate new heap for the size of the returned length.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, process_image_name, query_info_returned_length, &query_info_returned_length); // Now actually query the process image name.

		WCHAR log_buffer[1028]; // Initialize log buffer.

		snwprintf(log_buffer, RTL_NUMBER_OF(log_buffer), L"NtWriteVirtualMemory called for '%s'. BaseAddress: 0x%X, Buffer: 0x%X, BufferSize: 0x%X, NumberOfBytesRead: 0x%X, Result: 0x%X\n",
			process_image_name->Buffer, BaseAddress, Buffer, BufferSize, *NumberOfBytesRead, result);

		if (nt_write_virtual_memory_log) // Valid ptr?
			nt_write_virtual_memory_log->WriteToFile(log_buffer, (int)wcslen(log_buffer) * sizeof(wchar_t)); // Write log buffer to our file.

		RtlFreeHeap(RtlProcessHeap(), NULL, process_image_name); // Free the heap for process_image_name.

		return result;
	}

	NTSTATUS NTAPI hkNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
	{
		NTSTATUS result = Hooks::orig_nt_query_virtual_memory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

		if ((DWORD)BaseAddress > 0x7FFFFFFF) // Dont fuck with this if its in 64bit address space some will still come through sadly..
			return result; // return original.

		ULONG query_info_returned_length; // Initialize return length variable.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, NULL, &query_info_returned_length); // Query size for the ProcessImageFileName.

		UNICODE_STRING* process_image_name = (UNICODE_STRING*)RtlAllocateHeap(RtlProcessHeap(), NULL, query_info_returned_length); // Allocate new heap for the size of the returned length.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, process_image_name, query_info_returned_length, &query_info_returned_length); // Now actually query the process image name.

		WCHAR log_buffer[1028]; // Initialize log buffer.

		snwprintf(log_buffer, RTL_NUMBER_OF(log_buffer),
			L"NtQueryVirtualMemory called for '%s'. BaseAddress: 0x%X, MemoryInformationClass: %d, MemoryInformation: 0x%X, MemoryInformationLength: 0x%X, ReturnLength: 0x%X, Result: 0x%X\n",
			process_image_name->Buffer, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength, result);

		if (nt_query_virtual_memory_log) // Valid ptr?
			nt_query_virtual_memory_log->WriteToFile(log_buffer, (int)wcslen(log_buffer) * sizeof(wchar_t)); // Write log buffer to our file.

		RtlFreeHeap(RtlProcessHeap(), NULL, process_image_name); // Free the heap for process_image_name.

		return result;
	}
}

/*		PPEB peb = NtCurrentPeb(); // Get PEB.
		PEB_LDR_DATA* peb_ldr_data = peb->Ldr; // Get peb loader data.

		LIST_ENTRY* memory_order_module_list = &peb_ldr_data->InMemoryOrderModuleList; // Get memory module list.
		LIST_ENTRY* memory_order_module_list_head = memory_order_module_list; // Get start of memory module list.

		WCHAR* module_name = NULL; // Future module_name.

		do
		{
			PLDR_DATA_TABLE_ENTRY pldr_data_table_entry = CONTAINING_RECORD(memory_order_module_list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks); // Does current entry contain a record?

			if (pldr_data_table_entry)
			{
				size_t size_of_image = pldr_data_table_entry->SizeOfImage; // Get size of dll image.
				if ((size_t)*BaseAddress - (size_t)pldr_data_table_entry->DllBase < size_of_image) // Check if our baseaddress is in bounds of current looped module.
				{
					module_name = pldr_data_table_entry->BaseDllName.Buffer; // Found our module.
					break; // Break since we found our module.
				}
			}

			memory_order_module_list = memory_order_module_list->Flink; // Next entry.

		} while (memory_order_module_list_head != memory_order_module_list->Flink); // Check if entries are still valid

		ULONG query_info_returned_length; // Initialize return length variable.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, NULL, &query_info_returned_length); // Query size for the ProcessImageFileName.

		UNICODE_STRING* process_image_name = (UNICODE_STRING*)RtlAllocateHeap(RtlProcessHeap(), NULL, query_info_returned_length); // Allocate new heap for the size of the returned length.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, process_image_name, query_info_returned_length, &query_info_returned_length); // Now actually query the process image name.

		WCHAR log_buffer[1028]; // Initialize log buffer.

		// Fill log buffer with information of our hook.
		snwprintf(log_buffer, RTL_NUMBER_OF(log_buffer), L"'%s' called NtProtectVirtualMemory. BaseAddress: 0x%X in module '%s', RegionSize: 0x%X, NewProtect: 0x%X, OldProtect: 0x%X\n",
			process_image_name->Buffer, *BaseAddress, module_name, region_size_before_call, NewProtect, OldProtect);

		nt_protect_virtual_memory_log->WriteToFile(log_buffer, (int)wcslen(log_buffer) * sizeof(wchar_t)); // Write log buffer to our file.

		RtlFreeHeap(RtlProcessHeap(), NULL, process_image_name); // Free the heap for process_image_name.
*/


//	i++;
//	if (i == 19)
//	{
//		int* p = 0;
//		*p = 0;
//	}


/*		PPEB peb = NtCurrentPeb(); // Get PEB.
		PEB_LDR_DATA* peb_ldr_data = peb->Ldr; // Get peb loader data.

		LIST_ENTRY* memory_order_module_list = &peb_ldr_data->InMemoryOrderModuleList; // Get memory module list.
		LIST_ENTRY* memory_order_module_list_head = memory_order_module_list; // Get start of memory module list.

		WCHAR* module_name = NULL; // Future module_name.

		do
		{
			PLDR_DATA_TABLE_ENTRY pldr_data_table_entry = CONTAINING_RECORD(memory_order_module_list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks); // Does current entry contain a record?

			if (pldr_data_table_entry)
			{
				size_t size_of_image = pldr_data_table_entry->SizeOfImage; // Get size of dll image.
				if ((size_t)BaseAddress - (size_t)pldr_data_table_entry->DllBase < size_of_image) // Check if our baseaddress is in bounds of current looped module.
				{
					module_name = pldr_data_table_entry->BaseDllName.Buffer; // Found our module.
					break; // Break since we found our module.
				}
			}

			memory_order_module_list = memory_order_module_list->Flink; // Next entry.

		} while (memory_order_module_list_head != memory_order_module_list->Flink); // Check if entries are still valid*/