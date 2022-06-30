#pragma once
#include <driver/include.h>
#include <core/framework.h>



namespace process
{
	PEPROCESS get_by_id(uint32_t pid, NTSTATUS *pstatus = nullptr);
}