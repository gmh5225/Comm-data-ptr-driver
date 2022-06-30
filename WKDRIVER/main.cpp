#include <driver/include.h>
#include <driver/xorstr.h>

#include <system/funcs.h>
#include <core/hook.h>



extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
{
	if (system::get_loaded_module(XORS(L"easyanticheat.sys")) ||
		system::get_loaded_module(XORS(L"bedaisy.sys")) ||
		system::get_loaded_module(XORS(L"vgk.sys")))
	{
		ExRaiseStatus(STATUS_ABANDONED);
		ExRaiseAccessViolation();
		*(uint32_t *)0 = 0x13376969;
		return 0xBADC0DE;
	}

	uintptr_t win32kbase = system::get_system_module(XORS(L"win32kbase.sys"));
	if (!win32kbase)
	{
		printf("win32kbase.sys not found in system modules, unable to load driver.\n");
		return STATUS_ABANDONED;
	}

	uintptr_t target_func = system::get_routine_address(win32kbase, XORS("NtGdiPolyPolyDraw"));
	if (!target_func)
	{
		printf("unable to find target function in exports of win32kbase.sys.\n");
		return STATUS_UNSUCCESSFUL;
	}


	target_func += 0x366; // Offset

	//48 8B 05 FB B9 18 00                          mov     rax, cs:qword_1C0251838
	core_hook::fptr_addr = (uintptr_t)target_func + *(uint32_t *)((uint8_t *)target_func + 3) + 7;
	core_hook::o_fptr = (core_hook::pfunc_hk_t)InterlockedExchangePointer((volatile PVOID *)core_hook::fptr_addr, &core_hook::hooked_fptr);
	
	printf("driver successfully loaded.\n");
	return STATUS_SUCCESS;
}