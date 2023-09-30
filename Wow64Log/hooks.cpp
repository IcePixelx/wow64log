#include "hooks.h"
#include "ntdll.h"
#include <detours.h>
#include "defines.h"

namespace Hooks
{
	namespace
	{
		Logging* nt_read_virtual_memory_log;
	}

	decltype(NtReadVirtualMemory)* orig_nt_read_virtual_memory = nullptr;

	void EnableHooking()
	{
		DetourTransactionBegin();

		Hooks::orig_nt_read_virtual_memory = NtReadVirtualMemory;

		DetourAttach((PVOID*)&Hooks::orig_nt_read_virtual_memory, Hooks::hkNtReadVirtualMemory);
		DetourTransactionCommit();
	}

	void DisableHooking()
	{
		DetourTransactionBegin();

		DetourDetach((PVOID*)&Hooks::orig_nt_read_virtual_memory, Hooks::hkNtReadVirtualMemory);
		DetourTransactionCommit();
	}

	void EnableLogging()
	{
		/*
		   We are initializing class instances here.
		   Please keep in mind if you set a folder path that it isn't protected by UAC. (User Account Control or in common terms the Admin Prompt)
		   Otherwise it will fail or you need to launch the programm as admin.
		*/
		nt_read_virtual_memory_log = (Logging*)RtlAllocateHeap(RtlProcessHeap(), NULL, sizeof(Logging));
		nt_read_virtual_memory_log->Setup(L"C:\\Users\\Public\\NtReadVirtualMemory.txt");
		NTSTATUS result = nt_read_virtual_memory_log->CreateFileHandle(FILE_GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT);
	}

	void DisableLogging()
	{
		if (nt_read_virtual_memory_log)
		{
			nt_read_virtual_memory_log->~Logging();
			RtlFreeHeap(RtlProcessHeap(), NULL, nt_read_virtual_memory_log);
		}
	}

	NTSTATUS NTAPI hkNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
	{
		NTSTATUS result = Hooks::orig_nt_read_virtual_memory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead); // call original.

		ULONG query_info_returned_length;
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, NULL, &query_info_returned_length);

		UNICODE_STRING* process_image_name = (UNICODE_STRING*)RtlAllocateHeap(RtlProcessHeap(), NULL, query_info_returned_length);
		NtQueryInformationProcess(ProcessHandle, ProcessImageFileName, process_image_name, query_info_returned_length, &query_info_returned_length);

		WCHAR log_buffer[1028];

		snwprintf_c(log_buffer, RTL_NUMBER_OF(log_buffer), L"NtReadVirtualMemory called for '%s'. BaseAddress: 0x%X, Buffer: 0x%X, BufferSize: 0x%X, NumberOfBytesRead: 0x%X, Result: 0x%X\n",
			process_image_name->Buffer, BaseAddress, Buffer, BufferSize, *NumberOfBytesRead, result);

		if (nt_read_virtual_memory_log)
			nt_read_virtual_memory_log->WriteToFile(log_buffer, (int)wcslen(log_buffer) * sizeof(wchar_t));

		RtlFreeHeap(RtlProcessHeap(), NULL, process_image_name);

		return result;
	}
}