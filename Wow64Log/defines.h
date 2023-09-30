#pragma once

using _wcsrchr = wchar_t* (__cdecl*)(const wchar_t* Str, wchar_t Ch);
using _snwprintf = int(__cdecl*)(wchar_t* buffer, size_t count, const wchar_t* format, ...);

inline _snwprintf snwprintf_c = nullptr;
inline _wcsrchr wcsrchr_c = nullptr;