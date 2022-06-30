#include "funcs.h"


PEPROCESS process::get_by_id(uint32_t pid, NTSTATUS *pstatus)
{
	PEPROCESS hProc;
	NTSTATUS status = PsLookupProcessByProcessId( ( HANDLE ) pid, &hProc );
	if ( !NT_SUCCESS( status ) )
	{
		if ( pstatus )
			*pstatus = status;
		return NULL;
	}
	return hProc;
}