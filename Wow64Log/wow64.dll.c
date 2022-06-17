// wow64.dll slightly reversed code, all this belongs to their respective owners and not myself.

NTSTATUS __fastcall ProcessInit(__int64 a1_arg)
{
  struct _PEB *peb_var; // rsi
  NTSTATUS result; // eax
  wchar_t *var_image_name; // rdi
  NTSTATUS var_status; // ebx
  struct _TEB *var_current_teb; // rcx
  __int64 v7; // rax
  NT_TIB *var_nt_tib; // rcx
  int v9; // eax
  bool v10; // zf

  peb_var = NtCurrentPeb();
  RtlInitializeSRWLock(&AlertByThreadIdEventLock);
  if ( !RtlCreateHashTable(&AlertByThreadIdEventHashTable, 0i64, 0i64) )
    return STATUS_INSUFFICIENT_RESOURCES;
  Wow64ProtectMrdata(0);
  *Wow64InfoPtr = 0x1000;
  Wow64pLoadLogDll();                           // dll gets init here
  InitializeContextMapper();
  result = Wow64InitializeEmulatedSystemInformation();
  if ( result >= STATUS_SUCCESS )
  {
    LODWORD(NtDll32Base) = LdrSystemDllInitBlock.Wow64SharedInformation.SharedNtdll32Base;
    Ntdll32LoaderInitRoutine = LdrSystemDllInitBlock.Wow64SharedInformation.SharedNtdll32LdrInitRoutine;
    Ntdll32KiUserExceptionDispatcher = LdrSystemDllInitBlock.Wow64SharedInformation.SharedNtdll32KiUserExceptionDispatcher;
    Ntdll32KiUserApcDispatcher = LdrSystemDllInitBlock.Wow64SharedInformation.SharedNtdll32UserApcDispatcher;
    Ntdll32KiUserCallbackDispatcher = LdrSystemDllInitBlock.Wow64SharedInformation.SharedNtdll32KiUserCallbackDispatcher;
    var_image_name = GetImageName();
    var_status = Wow64pInitializeFilePathRedirection();
    if ( var_status < STATUS_SUCCESS )
    {
      Wow64LogPrint(1u, "ProcessInit: Wow64pInitializeFilePathRedirection failed, error %x\n", var_status);
    }
    else
    {
      ServiceTables[0] = *&sdwhnt32;
      ServiceTables[1] = unk_1800372E0;
      ServiceTables[2] = xmmword_1800372F0;
      ServiceTables[6] = sdwhcon[0];
      ServiceTables[7] = sdwhcon[1];
      ServiceTables[8] = sdwhcon[2];
      ServiceTables[3] = sdwhwin32[0];
      ServiceTables[4] = sdwhwin32[1];
      ServiceTables[5] = sdwhwin32[2];
      ServiceTables[9] = *&sdwhbase;
      ServiceTables[10] = unk_1800372B0;
      ServiceTables[11] = unk_1800372C0;
      var_current_teb = NtCurrentTeb();
      v7 = var_current_teb->SpareUlong0;
      if ( v7 )
      {
        if ( v7 >= 0 )
          var_current_teb = (var_current_teb + v7);
      }
      else
      {
        var_current_teb = 0i64;
      }
      var_nt_tib = LODWORD(var_current_teb->NtTib.Self);
      v9 = peb_var->ActivationContextData;
      Peb32 = var_nt_tib;
      v10 = LODWORD(var_nt_tib[8].ArbitraryUserPointer) == 0;
      LODWORD(var_nt_tib[9].ExceptionList) = v9;
      LODWORD(var_nt_tib[9].StackBase) = peb_var->SystemDefaultActivationContextData;
      if ( v10 )
        LODWORD(var_nt_tib[8].ArbitraryUserPointer) = peb_var->pShimData;
      var_status = CpuLoadBinaryTranslator(*(a1_arg + 36), var_image_name);
      if ( var_status >= 0 )
        var_status = BtFuncs(var_image_name, &CpuThreadSize);
      if ( var_image_name != L"Unknown Image" )
        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, var_image_name);
      if ( var_status < 0 || (var_status = Wow64pInitializeCrossProcessMechanism(), var_status < 0) )
        Wow64LogPrint(1u, "ProcessInit: CpuProcessInit failed, error %x.\n", var_status);
      else
        Wow64ProtectMrdata(1);
    }
    result = var_status;
  }
  return result;
}

NTSTATUS __stdcall Wow64pLoadLogDll()
{
  __int64 var_sytem_root; // rax
  NTSTATUS result; // eax
  NTSTATUS var_status; // ebx
  PVOID var_base_addr; // [rsp+20h] [rbp-E0h] BYREF
  ULONG var_load_flags; // [rsp+28h] [rbp-D8h] BYREF
  struct _STRING Name; // [rsp+30h] [rbp-D0h] BYREF
  _UNICODE_STRING var_destination_string; // [rsp+40h] [rbp-C0h] BYREF
  WCHAR var_source_string[264]; // [rsp+50h] [rbp-B0h] BYREF

  var_base_addr = PTRNULL;
  var_sytem_root = RtlGetNtSystemRoot();
  result = RtlStringCbPrintfW(var_source_string, 0x208ui64, L"%s\\system32\\wow64log.dll", var_sytem_root);
  if ( result >= STATUS_SUCCESS )
  {
    RtlInitUnicodeString(&var_destination_string, var_source_string);
    var_load_flags = 0x80000000;
    var_status = LdrLoadDll(0i64, &var_load_flags, &var_destination_string, &var_base_addr);
    if ( var_status < STATUS_SUCCESS )
      goto LABEL_3;
    RtlInitAnsiString(&Name, "Wow64LogInitialize");
    var_status = LdrGetProcedureAddress(var_base_addr, &Name, 0, &pfnWow64LogInitialize);
    if ( var_status < STATUS_SUCCESS )
      goto LABEL_3;
    RtlInitAnsiString(&Name, "Wow64LogSystemService");
    var_status = LdrGetProcedureAddress(var_base_addr, &Name, 0, &pfnWow64LogSystemService);
    if ( var_status < STATUS_SUCCESS )
      goto LABEL_3;
    RtlInitAnsiString(&Name, "Wow64LogMessageArgList");
    var_status = LdrGetProcedureAddress(var_base_addr, &Name, 0, &pfnWow64LogMessageArgList);
    if ( var_status < STATUS_SUCCESS )
      goto LABEL_3;
    RtlInitAnsiString(&Name, "Wow64LogTerminate");
    var_status = LdrGetProcedureAddress(var_base_addr, &Name, 0, &pfnWow64LogTerminate);
    if ( var_status < STATUS_SUCCESS )
      goto LABEL_3;
    var_status = pfnWow64LogInitialize ? (pfnWow64LogInitialize)() : STATUS_NOT_IMPLEMENTED;
    if ( var_status < 0 )
    {
LABEL_3:
      pfnWow64LogInitialize = PTRNULL;
      pfnWow64LogSystemService = PTRNULL;
      pfnWow64LogMessageArgList = PTRNULL;
      pfnWow64LogTerminate = PTRNULL;
      if ( var_base_addr )
        LdrUnloadDll(var_base_addr);
    }
    result = var_status;
  }
  return result;
}