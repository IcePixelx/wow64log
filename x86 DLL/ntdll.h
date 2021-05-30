#pragma once
#ifndef _NTDLL_H
#define _NTDLL_H

#define NTDLL_NO_INLINE_INIT_STRING

#define EtwEventRegister __EtwEventRegisterIgnored

#include "phnt/phnt_windows.h"
#include "phnt/phnt.h"

#undef  EtwEventRegister

#endif
