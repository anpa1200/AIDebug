/*
 * AIDebug full-program Ghidra reconstruction
 * Input: assign_constant_optimized.exe
 * SHA-256: 1f3088de00cb909939eef131ff13c2b5e75111717b4117b8d105f7749ca11464
 * Architecture: x86-64 64-bit
 *
 * This is reconstructed C-like code, not recovered original source.
 * Function boundaries, types, names, parameters, and control flow
 * remain hypotheses that must be checked against machine instructions.
 */

/* ================================================================== */
/* Function sub_140001190 at 0x140001190 */
/* Backend: ghidra; language: c-like */

ulonglong FUN_140001190(undefined *param_1,undefined *param_2,ulonglong param_3,ulonglong param_4)

{
  int iVar1;
  bool bVar2;
  undefined8 *puVar3;
  int iVar4;
  longlong lVar5;
  longlong lVar6;
  undefined8 *puVar7;
  size_t sVar8;
  void *_Dst;
  ulonglong uVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  longlong lVar12;
  size_t _Size;
  undefined8 *puVar13;
  longlong unaff_GS_OFFSET;
  
  lVar12 = *(longlong *)(*(longlong *)(unaff_GS_OFFSET + 0x30) + 8);
  while( true ) {
    LOCK();
    lVar6 = 0;
    lVar5 = lVar12;
    if (DAT_140007040 != 0) {
      lVar6 = DAT_140007040;
      lVar5 = DAT_140007040;
    }
    DAT_140007040 = lVar5;
    UNLOCK();
    if (lVar6 == 0) break;
    if (lVar12 == lVar6) {
      bVar2 = true;
joined_r0x0001400011ec:
      if (DAT_140007048 == 1) {
        _amsg_exit(0x1f);
      }
      else if (DAT_140007048 == 0) {
        DAT_140007048 = 1;
        _initterm();
      }
      else {
        DAT_140007008 = 1;
      }
      if (DAT_140007048 == 1) {
        _initterm();
        DAT_140007048 = 2;
      }
      if (!bVar2) {
        LOCK();
        DAT_140007040 = 0;
        UNLOCK();
      }
      uVar9 = 0;
      uVar11 = 2;
      uVar10 = 0;
      tls_callback_0(0,2);
      FUN_140001950(uVar10,uVar11,uVar9,param_4);
      DAT_1400070d0 = SetUnhandledExceptionFilter(FUN_140001d00);
      FUN_1400025d0(FUN_140001000);
      FUN_140001760();
      iVar4 = DAT_140007028;
      iVar1 = DAT_140007028 + 1;
      _Size = (longlong)iVar1 * 8;
      puVar7 = malloc(_Size);
      puVar3 = DAT_140007020;
      puVar13 = puVar7;
      if (0 < iVar4) {
        lVar12 = 0;
        do {
          sVar8 = strlen(*(char **)((longlong)puVar3 + lVar12));
          _Dst = malloc(sVar8 + 1);
          *(void **)((longlong)puVar7 + lVar12) = _Dst;
          puVar13 = (undefined8 *)((longlong)puVar3 + lVar12);
          lVar12 = lVar12 + 8;
          memcpy(_Dst,(void *)*puVar13,sVar8 + 1);
        } while (_Size - 8 != lVar12);
        puVar13 = puVar7 + (longlong)iVar1 + -1;
      }
      *puVar13 = 0;
      DAT_140007020 = puVar7;
      FUN_140001560();
      *(undefined8 *)__initenv_exref = DAT_140007018;
      uVar9 = FUN_140002710();
      DAT_140007010 = (uint)uVar9;
      if (DAT_14000700c != 0) {
        if (DAT_140007008 != 0) {
          return uVar9;
        }
        _cexit();
        return (ulonglong)DAT_140007010;
      }
                    /* WARNING: Subroutine does not return */
      exit(DAT_140007010);
    }
    Sleep(1000);
  }
  bVar2 = false;
  goto joined_r0x0001400011ec;
}

/* ================================================================== */
/* Function sub_140001410 at 0x140001410 */
/* Backend: ghidra; language: c-like */

void entry(undefined *param_1,undefined *param_2,ulonglong param_3,ulonglong param_4)

{
  DAT_140007090 = 0;
  FUN_140001190(param_1,param_2,param_3,param_4);
  return;
}

/* ================================================================== */
/* Function example_assign_constant at 0x140001480 */
/* Backend: ghidra; language: c-like */

undefined8 example_assign_constant(void)

{
                    /* 0x1480  1  example_assign_constant */
  return 5;
}

/* ================================================================== */
/* Function sub_140001560 at 0x140001560 */
/* Backend: ghidra; language: c-like */

void FUN_140001560(void)

{
  if (DAT_140007030 != 0) {
    return;
  }
  DAT_140007030 = 1;
  FUN_1400014e0();
  return;
}

/* ================================================================== */
/* Function sub_140001760 at 0x140001760 */
/* Backend: ghidra; language: c-like */

void FUN_140001760(void)

{
  return;
}

/* ================================================================== */
/* Function sub_140001770 at 0x140001770 */
/* Backend: ghidra; language: c-like */

void FUN_140001770(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  FILE *pFVar1;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res10 = param_2;
  local_res18 = param_3;
  local_res20 = param_4;
  pFVar1 = FUN_1400025e0(2);
  fwrite("Mingw-w64 runtime failure:\n",1,0x1b,pFVar1);
  pFVar1 = FUN_1400025e0(2);
  vfprintf(pFVar1,param_1,(va_list)&local_res10);
                    /* WARNING: Subroutine does not return */
  abort();
}

/* ================================================================== */
/* Function sub_1400017e0 at 0x1400017e0 */
/* Backend: ghidra; language: c-like */

/* WARNING: Enum "SectionFlags": Some values do not have unique names */

void FUN_1400017e0(ulonglong param_1,undefined8 param_2,ulonglong param_3,ulonglong param_4)

{
  BOOL BVar1;
  DWORD DVar2;
  ulonglong *puVar3;
  IMAGE_SECTION_HEADER *pIVar4;
  undefined4 *puVar5;
  IMAGE_DOS_HEADER *pIVar6;
  SIZE_T SVar7;
  PDWORD lpflOldProtect;
  longlong lVar8;
  undefined8 uVar9;
  uint uVar10;
  _MEMORY_BASIC_INFORMATION local_58;
  
  lVar8 = (longlong)(int)DAT_1400070a4;
  if ((int)DAT_1400070a4 < 1) {
    lVar8 = 0;
  }
  else {
    param_4 = 0;
    puVar3 = (ulonglong *)(DAT_1400070a8 + 0x18);
    do {
      param_3 = *puVar3;
      if ((param_3 <= param_1) && (param_3 = param_3 + *(uint *)(puVar3[1] + 8), param_1 < param_3))
      {
        return;
      }
      uVar10 = (int)param_4 + 1;
      param_4 = (ulonglong)uVar10;
      puVar3 = puVar3 + 5;
    } while (uVar10 != DAT_1400070a4);
  }
  pIVar4 = FUN_140002290(param_1);
  if (pIVar4 == (IMAGE_SECTION_HEADER *)0x0) {
                    /* WARNING: Subroutine does not return */
    FUN_140001770("Address %p has no image-section",param_1,param_3,param_4);
  }
  lVar8 = lVar8 * 0x28;
  puVar5 = (undefined4 *)(DAT_1400070a8 + lVar8);
  *(IMAGE_SECTION_HEADER **)(puVar5 + 8) = pIVar4;
  *puVar5 = 0;
  pIVar6 = FUN_1400023d0();
  uVar10 = pIVar4->VirtualAddress;
  *(char **)(DAT_1400070a8 + 0x18 + lVar8) = pIVar6->e_magic + uVar10;
  SVar7 = VirtualQuery(pIVar6->e_magic + uVar10,&local_58,0x30);
  if (SVar7 != 0) {
    if (((local_58.Protect - 4 & 0xfffffffb) != 0) && ((local_58.Protect - 0x40 & 0xffffffbf) != 0))
    {
      uVar9 = 0x40;
      if (local_58.Protect == 2) {
        uVar9 = 4;
      }
      lpflOldProtect = (PDWORD)(lVar8 + DAT_1400070a8);
      *(PVOID *)(lpflOldProtect + 2) = local_58.BaseAddress;
      *(SIZE_T *)(lpflOldProtect + 4) = local_58.RegionSize;
      BVar1 = VirtualProtect(local_58.BaseAddress,local_58.RegionSize,(DWORD)uVar9,lpflOldProtect);
      if (BVar1 == 0) {
        DVar2 = GetLastError();
                    /* WARNING: Subroutine does not return */
        FUN_140001770("  VirtualProtect failed with code 0x%x",(ulonglong)DVar2,uVar9,lpflOldProtect
                     );
      }
    }
    DAT_1400070a4 = DAT_1400070a4 + 1;
    return;
  }
                    /* WARNING: Subroutine does not return */
  FUN_140001770("  VirtualQuery failed for %d bytes at address %p",
                (ulonglong)(pIVar4->Misc).PhysicalAddress,
                *(undefined8 *)(DAT_1400070a8 + 0x18 + lVar8),param_4);
}

/* ================================================================== */
/* Function sub_140001950 at 0x140001950 */
/* Backend: ghidra; language: c-like */

/* WARNING: Removing unreachable block (ram,0x0001400019e1) */
/* WARNING: Removing unreachable block (ram,0x000140001af0) */
/* WARNING: Removing unreachable block (ram,0x000140001af8) */
/* WARNING: Removing unreachable block (ram,0x000140001b06) */
/* WARNING: Removing unreachable block (ram,0x0001400019ed) */
/* WARNING: Removing unreachable block (ram,0x0001400019f7) */
/* WARNING: Removing unreachable block (ram,0x0001400019fa) */
/* WARNING: Removing unreachable block (ram,0x000140001a02) */
/* WARNING: Removing unreachable block (ram,0x000140001ca0) */
/* WARNING: Removing unreachable block (ram,0x000140001a0e) */
/* WARNING: Removing unreachable block (ram,0x000140001a1b) */
/* WARNING: Removing unreachable block (ram,0x000140001a8f) */
/* WARNING: Removing unreachable block (ram,0x000140001aac) */
/* WARNING: Removing unreachable block (ram,0x000140001aae) */
/* WARNING: Removing unreachable block (ram,0x000140001ab7) */
/* WARNING: Removing unreachable block (ram,0x000140001c10) */
/* WARNING: Removing unreachable block (ram,0x000140001ace) */
/* WARNING: Removing unreachable block (ram,0x000140001a30) */
/* WARNING: Removing unreachable block (ram,0x000140001a39) */
/* WARNING: Removing unreachable block (ram,0x000140001c92) */
/* WARNING: Removing unreachable block (ram,0x000140001a42) */
/* WARNING: Removing unreachable block (ram,0x000140001c20) */
/* WARNING: Removing unreachable block (ram,0x000140001c2e) */
/* WARNING: Removing unreachable block (ram,0x000140001a54) */
/* WARNING: Removing unreachable block (ram,0x000140001a65) */
/* WARNING: Removing unreachable block (ram,0x000140001a6e) */
/* WARNING: Removing unreachable block (ram,0x000140001a77) */
/* WARNING: Removing unreachable block (ram,0x000140001b10) */
/* WARNING: Removing unreachable block (ram,0x000140001c48) */
/* WARNING: Removing unreachable block (ram,0x000140001c56) */
/* WARNING: Removing unreachable block (ram,0x000140001b22) */
/* WARNING: Removing unreachable block (ram,0x000140001b33) */
/* WARNING: Removing unreachable block (ram,0x000140001b3c) */
/* WARNING: Removing unreachable block (ram,0x000140001b42) */
/* WARNING: Removing unreachable block (ram,0x000140001b5a) */
/* WARNING: Removing unreachable block (ram,0x000140001bb8) */
/* WARNING: Removing unreachable block (ram,0x000140001c38) */
/* WARNING: Removing unreachable block (ram,0x000140001c42) */
/* WARNING: Removing unreachable block (ram,0x000140001bc4) */
/* WARNING: Removing unreachable block (ram,0x000140001bdb) */
/* WARNING: Removing unreachable block (ram,0x000140001be4) */
/* WARNING: Removing unreachable block (ram,0x000140001ad3) */
/* WARNING: Removing unreachable block (ram,0x000140001bf7) */
/* WARNING: Removing unreachable block (ram,0x000140001a82) */
/* WARNING: Removing unreachable block (ram,0x000140001c60) */
/* WARNING: Removing unreachable block (ram,0x000140001c69) */
/* WARNING: Removing unreachable block (ram,0x000140001c70) */
/* WARNING: Removing unreachable block (ram,0x000140001c8d) */
/* WARNING: Removing unreachable block (ram,0x000140001b60) */
/* WARNING: Removing unreachable block (ram,0x000140001b6e) */
/* WARNING: Removing unreachable block (ram,0x000140001b80) */
/* WARNING: Removing unreachable block (ram,0x000140001b92) */
/* WARNING: Removing unreachable block (ram,0x000140001b9f) */
/* WARNING: Removing unreachable block (ram,0x000140001bb0) */

void FUN_140001950(undefined8 param_1,undefined8 param_2,ulonglong param_3,ulonglong param_4)

{
  ulonglong uVar1;
  undefined1 auStack_58 [24];
  
  if (DAT_1400070a0 == 0) {
    DAT_1400070a0 = 1;
    FUN_140002310();
    uVar1 = FUN_140002560();
    DAT_1400070a4 = 0;
    DAT_1400070a8 = auStack_58 + -uVar1;
  }
  return;
}

/* ================================================================== */
/* Function sub_140002290 at 0x140002290 */
/* Backend: ghidra; language: c-like */

/* WARNING: Enum "SectionFlags": Some values do not have unique names */

IMAGE_SECTION_HEADER * FUN_140002290(longlong param_1)

{
  IMAGE_SECTION_HEADER *pIVar1;
  
  pIVar1 = &IMAGE_SECTION_HEADER_140000188;
  while ((param_1 - 0x140000000U < (ulonglong)(uint)pIVar1->VirtualAddress ||
         ((ulonglong)(pIVar1->VirtualAddress + (pIVar1->Misc).PhysicalAddress) <=
          param_1 - 0x140000000U))) {
    pIVar1 = pIVar1 + 1;
    if (pIVar1 == (IMAGE_SECTION_HEADER *)&DAT_140000340) {
      return (IMAGE_SECTION_HEADER *)0x0;
    }
  }
  return pIVar1;
}

/* ================================================================== */
/* Function sub_140002310 at 0x140002310 */
/* Backend: ghidra; language: c-like */

/* WARNING: Removing unreachable block (ram,0x00014000232f) */

word FUN_140002310(void)

{
  return 0xb;
}

/* ================================================================== */
/* Function sub_1400023d0 at 0x1400023d0 */
/* Backend: ghidra; language: c-like */

/* WARNING: Removing unreachable block (ram,0x0001400023ef) */

IMAGE_DOS_HEADER * FUN_1400023d0(void)

{
  return &IMAGE_DOS_HEADER_140000000;
}

/* ================================================================== */
/* Function sub_140002560 at 0x140002560 */
/* Backend: ghidra; language: c-like */

ulonglong FUN_140002560(void)

{
  ulonglong in_RAX;
  ulonglong uVar1;
  undefined8 *puVar2;
  undefined8 local_res8 [4];
  
  puVar2 = local_res8;
  uVar1 = in_RAX;
  if (0xfff < in_RAX) {
    do {
      puVar2 = puVar2 + -0x200;
      *puVar2 = *puVar2;
      uVar1 = uVar1 - 0x1000;
    } while (0x1000 < uVar1);
  }
  *(undefined8 *)((longlong)puVar2 - uVar1) = *(undefined8 *)((longlong)puVar2 - uVar1);
  return in_RAX;
}

/* ================================================================== */
/* Function sub_1400025d0 at 0x1400025d0 */
/* Backend: ghidra; language: c-like */

undefined8 FUN_1400025d0(undefined8 param_1)

{
  undefined8 uVar1;
  
  uVar1 = DAT_140007170;
  LOCK();
  DAT_140007170 = param_1;
  UNLOCK();
  return uVar1;
}

/* ================================================================== */
/* Function sub_1400025e0 at 0x1400025e0 */
/* Backend: ghidra; language: c-like */

FILE * FUN_1400025e0(uint param_1)

{
  FILE *pFVar1;
  
  pFVar1 = __iob_func();
  return pFVar1 + param_1;
}

/* ================================================================== */
/* Function sub_140002620 at 0x140002620 */
/* Backend: ghidra; language: c-like */

FILE * __cdecl __iob_func(void)

{
  FILE *pFVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002620. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pFVar1 = __iob_func();
  return pFVar1;
}

/* ================================================================== */
/* Function sub_140002638 at 0x140002638 */
/* Backend: ghidra; language: c-like */

void __cdecl _amsg_exit(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x000140002638. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _amsg_exit(param_1);
  return;
}

/* ================================================================== */
/* Function sub_140002640 at 0x140002640 */
/* Backend: ghidra; language: c-like */

void __cdecl _cexit(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002640. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _cexit();
  return;
}

/* ================================================================== */
/* Function sub_140002648 at 0x140002648 */
/* Backend: ghidra; language: c-like */

void _initterm(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002648. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _initterm();
  return;
}

/* ================================================================== */
/* Function sub_140002650 at 0x140002650 */
/* Backend: ghidra; language: c-like */

_onexit_t __cdecl _onexit(_onexit_t _Func)

{
  _onexit_t p_Var1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002650. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  p_Var1 = _onexit(_Func);
  return p_Var1;
}

/* ================================================================== */
/* Function sub_140002658 at 0x140002658 */
/* Backend: ghidra; language: c-like */

void __cdecl abort(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002658. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
  abort();
  return;
}

/* ================================================================== */
/* Function sub_140002668 at 0x140002668 */
/* Backend: ghidra; language: c-like */

void __cdecl exit(int _Code)

{
                    /* WARNING: Could not recover jumptable at 0x000140002668. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
  exit(_Code);
  return;
}

/* ================================================================== */
/* Function sub_140002680 at 0x140002680 */
/* Backend: ghidra; language: c-like */

size_t __cdecl fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002680. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  sVar1 = fwrite(_Str,_Size,_Count,_File);
  return sVar1;
}

/* ================================================================== */
/* Function sub_140002688 at 0x140002688 */
/* Backend: ghidra; language: c-like */

void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002688. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pvVar1 = malloc(_Size);
  return pvVar1;
}

/* ================================================================== */
/* Function sub_140002690 at 0x140002690 */
/* Backend: ghidra; language: c-like */

void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002690. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}

/* ================================================================== */
/* Function sub_1400026a0 at 0x1400026a0 */
/* Backend: ghidra; language: c-like */

size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;
  
                    /* WARNING: Could not recover jumptable at 0x0001400026a0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  sVar1 = strlen(_Str);
  return sVar1;
}

/* ================================================================== */
/* Function sub_1400026b0 at 0x1400026b0 */
/* Backend: ghidra; language: c-like */

int __cdecl vfprintf(FILE *_File,char *_Format,va_list _ArgList)

{
  int iVar1;
  
                    /* WARNING: Could not recover jumptable at 0x0001400026b0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  iVar1 = vfprintf(_File,_Format,_ArgList);
  return iVar1;
}

/* ================================================================== */
/* Function sub_140002710 at 0x140002710 */
/* Backend: ghidra; language: c-like */

undefined8 FUN_140002710(void)

{
  FUN_140001560();
  return 5;
}
