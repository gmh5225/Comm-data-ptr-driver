#pragma once
#include <driver/include.h>



namespace memory
{
	ULONG_PTR get_kernel_dirbase();
	NTSTATUS read_virtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read);
	NTSTATUS write_virtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written);

	NTSTATUS write_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t *bytes_written);
	NTSTATUS read_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t *bytes_read);
}