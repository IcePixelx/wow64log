#pragma once
#include "logging.h"

namespace Hooks
{
	void EnableHooking();
	void DisableHooking();
	void EnableLogging();
	void DisableLogging();

	NTSTATUS NTAPI hkNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
}