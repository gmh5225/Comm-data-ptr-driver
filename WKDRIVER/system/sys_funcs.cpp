#include "funcs.h"


namespace system
{
	uintptr_t get_loaded_module(const wchar_t *name, PLDR_DATA_TABLE_ENTRY *entry)
	{
		if (!name || PsLoadedModuleList == NULL || IsListEmpty(PsLoadedModuleList))
			return NULL;

		UNICODE_STRING modName;
		RtlInitUnicodeString(&modName, name);

		for (PLIST_ENTRY pEntry = PsLoadedModuleList->Flink; pEntry != PsLoadedModuleList; pEntry = pEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY data = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (RtlEqualUnicodeString(&data->BaseDllName, &modName, TRUE))
			{
				if (entry)
					*entry = data;
				return (uintptr_t)data->DllBase;
			}
		}
		return NULL;
	}

	uintptr_t get_system_module(const wchar_t *name)
	{
		NTSTATUS status = STATUS_SUCCESS;
		ANSI_STRING s_name;
		UNICODE_STRING su_name;
		RtlInitUnicodeString(&su_name, name);
		RtlUnicodeStringToAnsiString(&s_name, &su_name, TRUE);

		PRTL_PROCESS_MODULES pModules = NULL;
		uint32_t szModules = 0;

		status = ZwQuerySystemInformation(SystemModuleInformation, 0, szModules, (PULONG)&szModules);
		if (!szModules)
		{
			RtlFreeAnsiString(&s_name);
			return 0;
		}

		pModules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, szModules);
		if (!pModules)
		{
			RtlFreeAnsiString(&s_name);
			return 0;
		}
		RtlZeroMemory(pModules, szModules);

		status = ZwQuerySystemInformation(SystemModuleInformation, pModules, szModules, (PULONG)&szModules);
		if (!NT_SUCCESS(status))
		{
			RtlFreeAnsiString(&s_name);
			ExFreePool(pModules);
			return 0;
		}

		uintptr_t modBase = 0;
		PRTL_PROCESS_MODULE_INFORMATION pMods = pModules->Modules;
		for (ULONG i = 0; i < pModules->NumberOfModules && !modBase; i++)
		{
			RTL_PROCESS_MODULE_INFORMATION pMod = pMods[i];
			char *fullPath = (char*)pMod.FullPathName;
			if (fullPath && strlen(fullPath) > 0)
			{
				int32_t lastFound = -1;
				char *baseFullPath = (char *)pMod.FullPathName;
				while (*fullPath != 0)
				{
					if (*fullPath == '\\')
						lastFound = (fullPath - baseFullPath) + 1;
					fullPath++;
				}

				if (lastFound >= 0)
					fullPath = baseFullPath + lastFound;
			}
			else continue;

			ANSI_STRING s_fullPath;
			RtlInitAnsiString(&s_fullPath, fullPath);
			if (RtlEqualString(&s_fullPath, &s_name, TRUE))
				modBase = (uintptr_t)pMod.ImageBase;
		}
		RtlFreeAnsiString(&s_name);
		ExFreePool(pModules);
		return modBase;
	}

	uintptr_t get_routine_address(uintptr_t image, const char *name)
	{
		if (!image || !name)
			return NULL;
		return (uintptr_t)RtlFindExportedRoutineByName((PVOID)image, name);
	}
}