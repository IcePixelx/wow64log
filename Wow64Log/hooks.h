#pragma once
#include "logging.h"

namespace Hooks
{
	void EnableHooking();
	void DisableHooking();
	NTSTATUS InitializeLogging(HANDLE ntdll_handle);

	// Hook functions.
	NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
	NTSTATUS NTAPI hkNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
}