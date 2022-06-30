#include "hook.h"
#include <memory/memory.h> //read_process_memory, write_process_memory
#include <process/funcs.h>
#include <system/funcs.h>




NTSTATUS GetModuleBaseAddress( int processId, const char *moduleName, uint64_t *baseAddress )
{
	ANSI_STRING ansiString;
	UNICODE_STRING compareString;
	KAPC_STATE state;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = NULL;
	system::PPEB pPeb = NULL;

	RtlInitAnsiString( &ansiString, moduleName );
	RtlAnsiStringToUnicodeString( &compareString, &ansiString, TRUE );

	printf( "Looking for module %d\n", processId );

	if ( !NT_SUCCESS( PsLookupProcessByProcessId( ( HANDLE ) processId, &process ) ) )
		return STATUS_UNSUCCESSFUL;

	printf( "Found process %d\n", processId );

	KeStackAttachProcess( process, &state );
	pPeb = process::PsGetProcessPeb( process );

	if ( pPeb )
	{
		system::PPEB_LDR_DATA pLdr = ( system::PPEB_LDR_DATA ) pPeb->Ldr;

		if ( pLdr )
		{
			for ( PLIST_ENTRY listEntry = ( PLIST_ENTRY ) pLdr->InLoadOrderModuleList.Flink;
				listEntry != &pLdr->InLoadOrderModuleList;
				listEntry = ( PLIST_ENTRY ) listEntry->Flink ) {
			
				system::PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD( listEntry, system::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
				printf( "%wZ\n", pEntry->BaseDllName );
				if ( RtlCompareUnicodeString( &pEntry->BaseDllName, &compareString, TRUE ) == 0 )
				{
					*baseAddress = ( uint64_t ) pEntry->DllBase;
					status = STATUS_SUCCESS;
					break;
				}
			}
		}
	}
	KeUnstackDetachProcess( &state );
	RtlFreeUnicodeString( &compareString );
	return status;
}


__int64 __fastcall core_hook::hooked_fptr(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
	if (!a1 || ExGetPreviousMode() != UserMode)
	{
		printf("!a1 || ExGetPreviousMode() != UserMode fail. arguments: %p, %p, %p, %p\n", a1, a2, a3, a4);
		return 0;
	}

	if (a3 != fptr_data::static_identifier)
	{
		printf("arguments: % p, %p, %p, %p\n", a1, a2, a3, a4);
		if (o_fptr)
		{
			printf("original .data ptr call.\n");
			return o_fptr(a1, a2, a3, a4);
		}
		printf("Call failed static identifier check.\n");
		return 0;
	}

	// We in our territory now
	/*fptr_data::kernel_com com{};
	size_t read = 0;

	if (!NT_SUCCESS(memory::read_virtual(memory::get_kernel_dirbase(), a1, (uint8_t *)&com, sizeof(com), &read)) || read != sizeof(com))
	{
		printf("invalid memory sent to kernel for operation.\n");
		return 0;
	}*/
	fptr_data::kernel_com *com = (fptr_data::kernel_com *)a1;
	com->error = fptr_data::kernel_err::no_error;

	switch (static_cast<fptr_data::kernel_opr>(a4))
	{
		case fptr_data::kernel_opr::unhook_driver:
		{
			InterlockedExchangePointer((volatile PVOID *)core_hook::fptr_addr, core_hook::o_fptr);
			printf("unloaded driver.\n");
			break;
		}
		case fptr_data::kernel_opr::get_process_base:
		{
			NTSTATUS status = STATUS_SUCCESS;

			PEPROCESS proc = process::get_by_id(com->target_pid, &status);
			if (!NT_SUCCESS(status))
			{
				com->error = fptr_data::kernel_err::invalid_process;
				com->success = false;

				printf("get_process_base failed: invalid process.\n");
				return 1;
			}

			com->buffer = (uintptr_t)process::PsGetProcessSectionBaseAddress(proc);
			ObDereferenceObject(proc);
			break;
		}
		case fptr_data::kernel_opr::get_process_module:
		{
			// Inputs
			if (!com->target_pid)
			{
				com->error = fptr_data::kernel_err::invalid_data;
				com->success = false;
				printf("get_process_module failed: no valid process id given.\n");
				break;
			}


			uintptr_t buffer = 0;
			com->buffer = 0;
			if ( NT_SUCCESS( GetModuleBaseAddress( com->target_pid, com->name, &buffer ) ) )
				com->buffer = buffer;
			break;
			
			break;
		}
		case fptr_data::kernel_opr::write:
		{
			if (!NT_SUCCESS(memory::write_process_memory(com->target_pid, com->user_pid, com->address, com->buffer, com->size, &com->transfer)))
			{
				com->success = false;
				com->error = fptr_data::kernel_err::invalid_data;
				printf("write failed: invalid data.\n");
				return 1;
			}
			break;
		}
		case fptr_data::kernel_opr::read:
		{
			if (!NT_SUCCESS(memory::read_process_memory(com->target_pid, com->user_pid, com->address, com->buffer, com->size, &com->transfer)))
			{
				com->success = false;
				com->error = fptr_data::kernel_err::invalid_data;
				printf("read failed: invalid data.\n");
				return 1;
			}
			break;
		}



		case fptr_data::kernel_opr::protect:
		{
			NTSTATUS status = STATUS_SUCCESS;
			PEPROCESS hProc = process::get_by_id(com->target_pid, &status);
			if (!NT_SUCCESS(status) || !hProc)
			{
				com->success = false;
				com->error = fptr_data::kernel_err::check_fail;
				return 1;
			}

			void *addr = (void *)com->address;
			uint64_t size = com->size;
			uint32_t oldProtection = 0;
			uint32_t protection = com->buffer; // no condoms oke

			KAPC_STATE state;
			KeStackAttachProcess(hProc, &state);

			MEMORY_BASIC_INFORMATION mbi;
			if (!NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), NULL)))
			{
				KeUnstackDetachProcess(&state);
				com->success = false;
				com->error = fptr_data::kernel_err::check_fail;
				return 1;
			}

			if (mbi.Protect != com->buffer)
			{
				if (!NT_SUCCESS(memory::ZwProtectVirtualMemory(ZwCurrentProcess(), &addr, (PULONG)&size, protection, (PULONG)&oldProtection)))
				{
					KeUnstackDetachProcess(&state);
					com->success = false;
					com->error = fptr_data::kernel_err::check_fail;
					return 1;
				}
				KeUnstackDetachProcess(&state);
				ObDereferenceObject(hProc);

				com->buffer = oldProtection;
			}
			else
			{
				KeUnstackDetachProcess(&state);
				ObDereferenceObject(hProc);

				com->buffer = mbi.Protect;
			}
			break;
		}
		case fptr_data::kernel_opr::alloc:
		{
			NTSTATUS status = STATUS_SUCCESS;
			PEPROCESS hProc = process::get_by_id(com->target_pid, &status);
			if (!NT_SUCCESS(status) || !hProc)
			{
				com->success = false;
				com->error = fptr_data::kernel_err::check_fail;
				return 1;
			}

			uintptr_t addr, size, buffer, user_pid;
			addr = com->address;
			size = com->size;
			buffer = com->buffer;
			user_pid = com->user_pid;

			KAPC_STATE state;
			KeStackAttachProcess(hProc, &state);
			status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID *)&addr, 0, &size, buffer, user_pid);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&state);
				ObDereferenceObject(hProc);
				com->success = false;
				com->error = fptr_data::kernel_err::check_fail;
				return 1;
			}
			KeUnstackDetachProcess(&state);

			com->address = addr;
			com->size = size;

			ObDereferenceObject(hProc);
			break;
		}
		case fptr_data::kernel_opr::free:
		{
			NTSTATUS status = STATUS_SUCCESS;
			PEPROCESS hProc = process::get_by_id(com->target_pid, &status);
			if (!NT_SUCCESS(status) || !hProc)
			{
				com->success = false;
				com->error = fptr_data::kernel_err::check_fail;
				return 1;
			}

			uintptr_t addr, size;
			addr = com->address;
			size = 0;

			KAPC_STATE state;
			KeStackAttachProcess(hProc, &state);
			if (!NT_SUCCESS(ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID *)&addr, &size, MEM_RELEASE)))
			{
				KeUnstackDetachProcess(&state);
				com->success = false;
				com->error = fptr_data::kernel_err::check_fail;
				return 1;
			}
			KeUnstackDetachProcess(&state);
			ObDereferenceObject(hProc);
			break;
		}

		default:
		{
			com->success = false;
			com->error = fptr_data::kernel_err::no_operation;
			printf("(%p) failed: unknown operation.\n", a4);
			return 1;
		}
	}

	com->success = true;
	printf("kernel operation completed successfully.\n");
	return 1; //doesn't actually matter what this is (just >0)
}