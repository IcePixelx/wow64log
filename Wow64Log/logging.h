#pragma once
#include "ntdll.h"

class Logging
{
public:
	Logging() : file_path(UNICODE_STRING{}), file_handle(INVALID_HANDLE_VALUE), object_attributes(OBJECT_ATTRIBUTES{}), io_status(IO_STATUS_BLOCK{}) { }
	Logging(const wchar_t* path) : file_handle(INVALID_HANDLE_VALUE)
	{
		RtlDosPathNameToNtPathName_U(path, &file_path, NULL, NULL); // Convert path to NT Path.

		memset(&io_status, NULL, sizeof(io_status)); // Set to proper size.
		memset(&object_attributes, NULL, sizeof(object_attributes)); // Set to proper size.
		object_attributes.Length = sizeof(object_attributes); // Set to proper size.
		object_attributes.Attributes = OBJ_CASE_INSENSITIVE; // Set case insensitive flag.
		object_attributes.ObjectName = &file_path; // Object name is supposed to be file path.
	}

	~Logging()
	{

		memset(&io_status, NULL, sizeof(io_status)); // Empty the memory.
		memset(&object_attributes, NULL, sizeof(object_attributes)); // Empty the memory.

		if (file_handle != INVALID_HANDLE_VALUE) // If handle got opened close it.
		{
			NtClose(file_handle);
		}
	}

	void Setup(const wchar_t* path)
	{
		RtlDosPathNameToNtPathName_U(path, &file_path, NULL, NULL); // Convert path to NT Path.

		memset(&io_status, NULL, sizeof(io_status)); // Set to proper size.
		memset(&object_attributes, NULL, sizeof(object_attributes)); // Set to proper size.
		object_attributes.Length = sizeof(object_attributes); // Set to proper size.
		object_attributes.Attributes = OBJ_CASE_INSENSITIVE; // Set case insensitive flag.
		object_attributes.ObjectName = &file_path; // Object name is supposed to be file path.
		file_handle = INVALID_HANDLE_VALUE;
	}

	NTSTATUS CreateFileHandle(ACCESS_MASK desired_access, ULONG file_attributes, ULONG share_access, ULONG create_disposition, ULONG create_options)
	{
		if (file_handle != INVALID_HANDLE_VALUE) // Handle already got created.
			return -1;

		return NtCreateFile(&file_handle, desired_access, &object_attributes, &io_status, NULL, file_attributes, share_access, create_disposition, create_options, NULL, NULL); // Create file handle.
	};

	NTSTATUS WriteToFile(PVOID buffer, int buffer_length)
	{
		if (!buffer) // Is buffer valid?
			return -2;

		if (file_handle == INVALID_HANDLE_VALUE) // Invalid handle?
			return -3;

		return NtWriteFile(file_handle, NULL, NULL, NULL, &io_status, buffer, buffer_length, NULL, NULL); // Write to file.
	};

	HANDLE GetFileHandle()
	{
		return file_handle;
	};

	UNICODE_STRING GetFilePath()
	{
		return file_path;
	}

private:
	UNICODE_STRING file_path;
	HANDLE file_handle;
	OBJECT_ATTRIBUTES object_attributes;
	IO_STATUS_BLOCK io_status;
};