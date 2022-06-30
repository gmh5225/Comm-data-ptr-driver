#include "phys.h"


// Thank you Astronaut00, I promise I will learn from this one day.
// I actually mean that though, I just need this for now
//https://github.com/Astronaut00/DoubleDataPointer/blob/master/Driver/core.cpp


//https://ntdiff.github.io/
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

DWORD GetUserDirectoryTableBaseOffset()
{
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);

	switch (ver.dwBuildNumber)
	{
		case WINDOWS_1803:
			return 0x0278;
			break;
		case WINDOWS_1809:
			return 0x0278;
			break;
		case WINDOWS_1903:
			return 0x0280;
			break;
		case WINDOWS_1909:
			return 0x0280;
			break;
		case WINDOWS_2004:
			return 0x0388;
			break;
		case WINDOWS_20H2:
			return 0x0388;
			break;
		case WINDOWS_21H1:
			return 0x0388;
			break;
		default:
			return 0x0388;
	}
}

//check normal dirbase if 0 then get from UserDirectoryTableBas
ULONG_PTR get_process_cr3(PEPROCESS pProcess)
{
	PUCHAR process = (PUCHAR)pProcess;
	ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
	if (process_dirbase == 0)
	{
		DWORD UserDirOffset = GetUserDirectoryTableBaseOffset();
		ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
		return process_userdirbase;
	}
	return process_dirbase;
}
ULONG_PTR memory::get_kernel_dirbase()
{
	PUCHAR process = (PUCHAR)PsGetCurrentProcess();
	ULONG_PTR cr3 = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
	return cr3;
}
uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress);
NTSTATUS ReadPhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
NTSTATUS WritePhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);


NTSTATUS memory::read_virtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read)
{
	uint64_t paddress = TranslateLinearAddress(dirbase, address);
	return ReadPhysicalAddress(paddress, buffer, size, read);
}

NTSTATUS memory::write_virtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written)
{
	uint64_t paddress = TranslateLinearAddress(dirbase, address);
	return WritePhysicalAddress(paddress, buffer, size, written);
}

NTSTATUS ReadPhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS AddrToRead = { 0 };
	AddrToRead.PhysicalAddress.QuadPart = TargetAddress;
	return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

//MmMapIoSpaceEx limit is page 4096 byte
NTSTATUS WritePhysicalAddress(uint64_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	if (!TargetAddress)
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = TargetAddress;

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	memcpy(pmapped_mem, lpBuffer, Size);

	if (BytesWritten) *BytesWritten = Size;
	MmUnmapIoSpace(pmapped_mem, Size);
	return STATUS_SUCCESS;
}

#define PAGE_OFFSET_SIZE 12
static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress) {
	directoryTableBase &= ~0xf;

	uint64_t pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	uint64_t pte = ((virtualAddress >> 12) & (0x1ffll));
	uint64_t pt = ((virtualAddress >> 21) & (0x1ffll));
	uint64_t pd = ((virtualAddress >> 30) & (0x1ffll));
	uint64_t pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	uint64_t pdpe = 0;
	ReadPhysicalAddress(directoryTableBase + 8 * pdp, &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	uint64_t pde = 0;
	ReadPhysicalAddress((pdpe & PMASK) + 8 * pd, &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	uint64_t pteAddr = 0;
	ReadPhysicalAddress((pde & PMASK) + 8 * pt, &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	ReadPhysicalAddress((pteAddr & PMASK) + 8 * pte, &virtualAddress, sizeof(virtualAddress), &readsize);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}


//
NTSTATUS ReadProcessMemory(int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* read)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = get_process_cr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{

		uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesRead = 0;
		NtRet = ReadPhysicalAddress(CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
		TotalSize -= BytesRead;
		CurOffset += BytesRead;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesRead == 0) break;
	}

	*read = CurOffset;
	return NtRet;
}

NTSTATUS WriteProcessMemory(int pid, uint64_t Address, uint64_t AllocatedBuffer, SIZE_T size, SIZE_T* written)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = get_process_cr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{
		uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesWritten = 0;
		NtRet = WritePhysicalAddress(CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
		TotalSize -= BytesWritten;
		CurOffset += BytesWritten;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesWritten == 0) break;
	}

	*written = CurOffset;
	return NtRet;
}



namespace memory
{
	NTSTATUS write_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t *bytes_written)
	{
		NTSTATUS status = STATUS_SUCCESS;
		size_t btransfer;
		status = WriteProcessMemory(pid, addr, buffer, size, &btransfer);
		if (bytes_written)
			*bytes_written = btransfer;
		return status;
	}

	NTSTATUS read_process_memory(uint32_t pid, uintptr_t addr, uintptr_t buffer, size_t size, size_t *bytes_read)
	{
		NTSTATUS status = STATUS_SUCCESS;
		size_t btransfer;
		status = ReadProcessMemory(pid, addr, buffer, size, &btransfer);
		if (bytes_read)
			*bytes_read = btransfer;
		return status;
	}
}