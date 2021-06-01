#include "hooks.h"
#include "ntdll.h"
#include <detours.h>
#include "defines.h"

namespace Hooks
{
	namespace
	{
		Logging* NtAllocateVirtualMemoryLog;
		_snwprintf snwprintf = nullptr;
	}

	// Original functions.
	decltype(NtAllocateVirtualMemory)* orig_nt_allocate_virtual_memory = nullptr;

	// Start hooks.
	void EnableHooking()
	{
		DetourTransactionBegin();
		Hooks::orig_nt_allocate_virtual_memory = NtAllocateVirtualMemory;
		DetourAttach((PVOID*)&Hooks::orig_nt_allocate_virtual_memory, Hooks::hkNtAllocateVirtualMemory);
		DetourTransactionCommit();
	}

	// Stop hooks.
	void DisableHooking()
	{
		DetourTransactionBegin();
		DetourDetach((PVOID*)&Hooks::orig_nt_allocate_virtual_memory, Hooks::hkNtAllocateVirtualMemory);
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

		NtAllocateVirtualMemoryLog = (Logging*)RtlAllocateHeap(RtlProcessHeap(), NULL, sizeof(Logging)); // All heap for class instance.
		NtAllocateVirtualMemoryLog->Setup(L"C:\\Users\\Public\\NtAllocateVirtualMemoryLog.txt"); // Create Logging class instance.
		result = NtAllocateVirtualMemoryLog->CreateFileHandle(FILE_GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT); // Create file handle.
		if (!NT_SUCCESS(result)) // Did CreateFileHandle succeed?
			return result;

		return STATUS_SUCCESS; 
	}

	// Hook functions.
	NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
	{
		SIZE_T region_size_before_call = *RegionSize; // Grab RegionSize before original modifies it.

		NTSTATUS result = Hooks::orig_nt_allocate_virtual_memory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect); // call original to get BaseAddress allocation.

		if ((size_t)BaseAddress > 0x7FFFFFFF) // Dont fuck with this if its in 64bit address space. 
			return result; // return original.

		ULONG query_info_returned_length; // Initialize return length variable.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, NULL, &query_info_returned_length); // Query size for the ProcessImageFileName.

		UNICODE_STRING* process_image_name = (UNICODE_STRING*)RtlAllocateHeap(RtlProcessHeap(), NULL, query_info_returned_length); // Allocate new heap for the size of the returned length.
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, process_image_name, query_info_returned_length, &query_info_returned_length); // Now actually query the process image name.

		WCHAR log_buffer[1028]; // Initialize log buffer.

		// Fill log buffer with information of our hook.
		snwprintf(log_buffer, RTL_NUMBER_OF(log_buffer), L"'%s' called NtAllocateVirtualMemory. BaseAddress: 0x%X, RegionSize: 0x%X, AllocationType: 0x%X, Protect: 0x%X\n",
			process_image_name->Buffer, *BaseAddress, region_size_before_call, AllocationType, Protect);

		NtAllocateVirtualMemoryLog->WriteToFile(log_buffer, (int)wcslen(log_buffer) * sizeof(wchar_t)); // Write log buffer to our file.

		RtlFreeHeap(RtlProcessHeap(), NULL, process_image_name); // Free the heap for process_image_name.

		PPEB peb = NtCurrentPeb(); // Get PEB.
		PEB_LDR_DATA* peb_ldr_data = peb->Ldr; // Get peb loader data.

		LIST_ENTRY* memory_order_module_list = &peb_ldr_data->InMemoryOrderModuleList; // Get memory module list.
		LIST_ENTRY* memory_order_module_list_head = memory_order_module_list; // Get start of memory module list.

		const WCHAR* module_name = NULL; // Future module_name.

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

		} while (memory_order_module_list_head != memory_order_module_list->Flink); // Check if entries are still valid

		return result; // return original.
	}
}