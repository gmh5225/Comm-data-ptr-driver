#pragma once
#include <driver/defs.h>
#include <driver/include.h>
#include <system/funcs.h>



namespace core_hook
{
	typedef __int64(__fastcall *pfunc_hk_t)(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);


	inline uintptr_t fptr_addr = NULL;
	inline pfunc_hk_t o_fptr = (pfunc_hk_t)NULL;


	/* All information about this .data ptr:
	
	NtGdiPolyPolyDraw + 0x366 is the fptr.
	
	if ( qword_1C0251830 )
	{
		v21 = qword_1C0251830(); <--- another fptr, possible to hook if wanted.
		v9 = -1073741637;
		a1 = v25;
	}
	else
	{
		v9 = -1073741637;
		v21 = -1073741637;
	}
	if ( v21 < 0 )
		return v8;
	v22 = (int)qword_1C0251838;
	if ( qword_1C0251838 )
		v22 = qword_1C0251838(a1, v7, v6, (unsigned int)v5); <--- hooked fptr    a1 = a1, v7 = a2, v6 = a3, v5 = (unsigned)(a4 [!>0])
	if ( v22 )
		return v8;

	a5 when calling NtGdiPolyPolyDraw must be 2.

	!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	!! a4 CAN *NOT* be NULL or else it will immediately return 0. Any other value is acceptable. !!
	!! a4 CAN *NOT* be NULL or else it will immediately return 0. Any other value is acceptable. !!
	!! a4 CAN *NOT* be NULL or else it will immediately return 0. Any other value is acceptable. !!
	!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	a1-a3 are free to use however you want *as they have no effect until it reaches the hooked_fptr*.


	when hooked_fptr returns non-null value, the function will return 1.
	when hooked_fptr returns 0, it will continue throughout the function (normally returns 0, but suggest returning 1 always).
	
	a1 = kernel_com
	a2   -- unused
	a3 = 0xBADC0DE
	a4 = control code
	*/
	__int64 __fastcall hooked_fptr(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
}