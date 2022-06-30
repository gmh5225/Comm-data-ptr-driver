#pragma once
#include <driver/include.h>
#include <core/framework.h>



namespace system
{
	uintptr_t get_loaded_module(const wchar_t *name, PLDR_DATA_TABLE_ENTRY *entry = nullptr);
	uintptr_t get_system_module(const wchar_t *name);
	uintptr_t get_routine_address(uintptr_t image, const char *name);
}