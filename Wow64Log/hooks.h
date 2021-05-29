#pragma once

namespace Hooks
{
	void EnableHooking();

	// Hook functions.
	NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
}