#include "hooks.h"
#include "ntdll.h"
#include <detours.h>

namespace Hooks
{
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

	// Hook functions.
	NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
	{
		NTSTATUS result = Hooks::orig_nt_allocate_virtual_memory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect); // call original to get BaseAddress allocation.

		if ((size_t)BaseAddress > 0x7FFFFFFF) // Dont fuck with this if its in 64bit address space. 
			return result; // return original.

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