#pragma once
#include <driver/include.h>
#include <stdint.h>

namespace system
{
	// Process Environment Block
	typedef struct _PEB_LDR_DATA
	{
		ULONG Length;
		UCHAR Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;


	typedef struct _IMAGE_FILE_HEADER {
		WORD    Machine;
		WORD    NumberOfSections;
		DWORD   TimeDateStamp;
		DWORD   PointerToSymbolTable;
		DWORD   NumberOfSymbols;
		WORD    SizeOfOptionalHeader;
		WORD    Characteristics;
	} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

	typedef struct _IMAGE_DATA_DIRECTORY {
		DWORD   VirtualAddress;
		DWORD   Size;
	} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
	typedef struct _IMAGE_OPTIONAL_HEADER64 {
		WORD        Magic;
		BYTE        MajorLinkerVersion;
		BYTE        MinorLinkerVersion;
		DWORD       SizeOfCode;
		DWORD       SizeOfInitializedData;
		DWORD       SizeOfUninitializedData;
		DWORD       AddressOfEntryPoint;
		DWORD       BaseOfCode;
		ULONGLONG   ImageBase;
		DWORD       SectionAlignment;
		DWORD       FileAlignment;
		WORD        MajorOperatingSystemVersion;
		WORD        MinorOperatingSystemVersion;
		WORD        MajorImageVersion;
		WORD        MinorImageVersion;
		WORD        MajorSubsystemVersion;
		WORD        MinorSubsystemVersion;
		DWORD       Win32VersionValue;
		DWORD       SizeOfImage;
		DWORD       SizeOfHeaders;
		DWORD       CheckSum;
		WORD        Subsystem;
		WORD        DllCharacteristics;
		ULONGLONG   SizeOfStackReserve;
		ULONGLONG   SizeOfStackCommit;
		ULONGLONG   SizeOfHeapReserve;
		ULONGLONG   SizeOfHeapCommit;
		DWORD       LoaderFlags;
		DWORD       NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

	typedef struct _IMAGE_NT_HEADERS64 {
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;


	typedef struct _IMAGE_DOS_HEADER
	{
		WORD e_magic;
		WORD e_cblp;
		WORD e_cp;
		WORD e_crlc;
		WORD e_cparhdr;
		WORD e_minalloc;
		WORD e_maxalloc;
		WORD e_ss;
		WORD e_sp;
		WORD e_csum;
		WORD e_ip;
		WORD e_cs;
		WORD e_lfarlc;
		WORD e_ovno;
		WORD e_res[4];
		WORD e_oemid;
		WORD e_oeminfo;
		WORD e_res2[10];
		LONG e_lfanew;
	} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

#define IMAGE_SIZEOF_SHORT_NAME              8
	typedef struct _IMAGE_SECTION_HEADER {
		BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
		union {
			DWORD   PhysicalAddress;
			DWORD   VirtualSize;
		} Misc;
		DWORD   VirtualAddress;
		DWORD   SizeOfRawData;
		DWORD   PointerToRawData;
		DWORD   PointerToRelocations;
		DWORD   PointerToLinenumbers;
		WORD    NumberOfRelocations;
		WORD    NumberOfLinenumbers;
		DWORD   Characteristics;
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_FIRST_SECTION( ntheader ) ((System::PIMAGE_SECTION_HEADER)  \
    ((ULONG_PTR)(ntheader) +                                      \
     FIELD_OFFSET( System::IMAGE_NT_HEADERS, OptionalHeader ) +           \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))


	typedef struct _PEB
	{
		UCHAR InheritedAddressSpace;
		UCHAR ReadImageFileExecOptions;
		UCHAR BeingDebugged;
		UCHAR BitField;
		PVOID Mutant;
		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PVOID ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PVOID FastPebLock;
		PVOID AtlThunkSListPtr;
		PVOID IFEOKey;
		PVOID CrossProcessFlags;
		PVOID KernelCallbackTable;
		ULONG SystemReserved;
		ULONG AtlThunkSListPtr32;
		PVOID ApiSetMap;
	} PEB, *PPEB;


	// Loader
	typedef struct _NON_PAGED_DEBUG_INFO
	{
		USHORT      Signature;
		USHORT      Flags;
		ULONG       Size;
		USHORT      Machine;
		USHORT      Characteristics;
		ULONG       TimeDateStamp;
		ULONG       CheckSum;
		ULONG       SizeOfImage;
		ULONGLONG   ImageBase;
	} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		PVOID ExceptionTable;
		ULONG ExceptionTableSize;
		// ULONG padding on IA64
		PVOID GpValue;
		PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT __Unused5;
		PVOID SectionPointer;
		ULONG CheckSum;
		// ULONG padding on IA64
		PVOID LoadedImports;
		PVOID PatchInformation;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;



	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


	// Enums
	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation = 0x0,
		SystemProcessorInformation = 0x1,
		SystemPerformanceInformation = 0x2,
		SystemTimeOfDayInformation = 0x3,
		SystemPathInformation = 0x4,
		SystemProcessInformation = 0x5,
		SystemCallCountInformation = 0x6,
		SystemDeviceInformation = 0x7,
		SystemProcessorPerformanceInformation = 0x8,
		SystemFlagsInformation = 0x9,
		SystemCallTimeInformation = 0xa,
		SystemModuleInformation = 0xb,
		SystemLocksInformation = 0xc,
		SystemStackTraceInformation = 0xd,
		SystemPagedPoolInformation = 0xe,
		SystemNonPagedPoolInformation = 0xf,
		SystemHandleInformation = 0x10,
		SystemObjectInformation = 0x11,
		SystemPageFileInformation = 0x12,
		SystemVdmInstemulInformation = 0x13,
		SystemVdmBopInformation = 0x14,
		SystemFileCacheInformation = 0x15,
		SystemPoolTagInformation = 0x16,
		SystemInterruptInformation = 0x17,
		SystemDpcBehaviorInformation = 0x18,
		SystemFullMemoryInformation = 0x19,
		SystemLoadGdiDriverInformation = 0x1a,
		SystemUnloadGdiDriverInformation = 0x1b,
		SystemTimeAdjustmentInformation = 0x1c,
		SystemSummaryMemoryInformation = 0x1d,
		SystemMirrorMemoryInformation = 0x1e,
		SystemPerformanceTraceInformation = 0x1f,
		SystemObsolete0 = 0x20,
		SystemExceptionInformation = 0x21,
		SystemCrashDumpStateInformation = 0x22,
		SystemKernelDebuggerInformation = 0x23,
		SystemContextSwitchInformation = 0x24,
		SystemRegistryQuotaInformation = 0x25,
		SystemExtendServiceTableInformation = 0x26,
		SystemPrioritySeperation = 0x27,
		SystemVerifierAddDriverInformation = 0x28,
		SystemVerifierRemoveDriverInformation = 0x29,
		SystemProcessorIdleInformation = 0x2a,
		SystemLegacyDriverInformation = 0x2b,
		SystemCurrentTimeZoneInformation = 0x2c,
		SystemLookasideInformation = 0x2d,
		SystemTimeSlipNotification = 0x2e,
		SystemSessionCreate = 0x2f,
		SystemSessionDetach = 0x30,
		SystemSessionInformation = 0x31,
		SystemRangeStartInformation = 0x32,
		SystemVerifierInformation = 0x33,
		SystemVerifierThunkExtend = 0x34,
		SystemSessionProcessInformation = 0x35,
		SystemLoadGdiDriverInSystemSpace = 0x36,
		SystemNumaProcessorMap = 0x37,
		SystemPrefetcherInformation = 0x38,
		SystemExtendedProcessInformation = 0x39,
		SystemRecommendedSharedDataAlignment = 0x3a,
		SystemComPlusPackage = 0x3b,
		SystemNumaAvailableMemory = 0x3c,
		SystemProcessorPowerInformation = 0x3d,
		SystemEmulationBasicInformation = 0x3e,
		SystemEmulationProcessorInformation = 0x3f,
		SystemExtendedHandleInformation = 0x40,
		SystemLostDelayedWriteInformation = 0x41,
		SystemBigPoolInformation = 0x42,
		SystemSessionPoolTagInformation = 0x43,
		SystemSessionMappedViewInformation = 0x44,
		SystemHotpatchInformation = 0x45,
		SystemObjectSecurityMode = 0x46,
		SystemWatchdogTimerHandler = 0x47,
		SystemWatchdogTimerInformation = 0x48,
		SystemLogicalProcessorInformation = 0x49,
		SystemWow64SharedInformationObsolete = 0x4a,
		SystemRegisterFirmwareTableInformationHandler = 0x4b,
		SystemFirmwareTableInformation = 0x4c,
		SystemModuleInformationEx = 0x4d,
		SystemVerifierTriageInformation = 0x4e,
		SystemSuperfetchInformation = 0x4f,
		SystemMemoryListInformation = 0x50,
		SystemFileCacheInformationEx = 0x51,
		SystemThreadPriorityClientIdInformation = 0x52,
		SystemProcessorIdleCycleTimeInformation = 0x53,
		SystemVerifierCancellationInformation = 0x54,
		SystemProcessorPowerInformationEx = 0x55,
		SystemRefTraceInformation = 0x56,
		SystemSpecialPoolInformation = 0x57,
		SystemProcessIdInformation = 0x58,
		SystemErrorPortInformation = 0x59,
		SystemBootEnvironmentInformation = 0x5a,
		SystemHypervisorInformation = 0x5b,
		SystemVerifierInformationEx = 0x5c,
		SystemTimeZoneInformation = 0x5d,
		SystemImageFileExecutionOptionsInformation = 0x5e,
		SystemCoverageInformation = 0x5f,
		SystemPrefetchPatchInformation = 0x60,
		SystemVerifierFaultsInformation = 0x61,
		SystemSystemPartitionInformation = 0x62,
		SystemSystemDiskInformation = 0x63,
		SystemProcessorPerformanceDistribution = 0x64,
		SystemNumaProximityNodeInformation = 0x65,
		SystemDynamicTimeZoneInformation = 0x66,
		SystemCodeIntegrityInformation = 0x67,
		SystemProcessorMicrocodeUpdateInformation = 0x68,
		SystemProcessorBrandString = 0x69,
		SystemVirtualAddressInformation = 0x6a,
		SystemLogicalProcessorAndGroupInformation = 0x6b,
		SystemProcessorCycleTimeInformation = 0x6c,
		SystemStoreInformation = 0x6d,
		SystemRegistryAppendString = 0x6e,
		SystemAitSamplingValue = 0x6f,
		SystemVhdBootInformation = 0x70,
		SystemCpuQuotaInformation = 0x71,
		SystemNativeBasicInformation = 0x72,
		SystemErrorPortTimeouts = 0x73,
		SystemLowPriorityIoInformation = 0x74,
		SystemBootEntropyInformation = 0x75,
		SystemVerifierCountersInformation = 0x76,
		SystemPagedPoolInformationEx = 0x77,
		SystemSystemPtesInformationEx = 0x78,
		SystemNodeDistanceInformation = 0x79,
		SystemAcpiAuditInformation = 0x7a,
		SystemBasicPerformanceInformation = 0x7b,
		SystemQueryPerformanceCounterInformation = 0x7c,
		SystemSessionBigPoolInformation = 0x7d,
		SystemBootGraphicsInformation = 0x7e,
		SystemScrubPhysicalMemoryInformation = 0x7f,
		SystemBadPageInformation = 0x80,
		SystemProcessorProfileControlArea = 0x81,
		SystemCombinePhysicalMemoryInformation = 0x82,
		SystemEntropyInterruptTimingInformation = 0x83,
		SystemConsoleInformation = 0x84,
		SystemPlatformBinaryInformation = 0x85,
		SystemThrottleNotificationInformation = 0x86,
		SystemHypervisorProcessorCountInformation = 0x87,
		SystemDeviceDataInformation = 0x88,
		SystemDeviceDataEnumerationInformation = 0x89,
		SystemMemoryTopologyInformation = 0x8a,
		SystemMemoryChannelInformation = 0x8b,
		SystemBootLogoInformation = 0x8c,
		SystemProcessorPerformanceInformationEx = 0x8d,
		SystemSpare0 = 0x8e,
		SystemSecureBootPolicyInformation = 0x8f,
		SystemPageFileInformationEx = 0x90,
		SystemSecureBootInformation = 0x91,
		SystemEntropyInterruptTimingRawInformation = 0x92,
		SystemPortableWorkspaceEfiLauncherInformation = 0x93,
		SystemFullProcessInformation = 0x94,
		SystemKernelDebuggerInformationEx = 0x95,
		SystemBootMetadataInformation = 0x96,
		SystemSoftRebootInformation = 0x97,
		SystemElamCertificateInformation = 0x98,
		SystemOfflineDumpConfigInformation = 0x99,
		SystemProcessorFeaturesInformation = 0x9a,
		SystemRegistryReconciliationInformation = 0x9b,
		MaxSystemInfoClass = 0x9c,
	} SYSTEM_INFORMATION_CLASS;

	// Imports
	extern "C" __declspec(dllimport) PLIST_ENTRY PsLoadedModuleList;

	extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	extern "C" PVOID NTAPI RtlFindExportedRoutineByName(PVOID ImageBase, PCCH RoutineName);
}

namespace process
{
	// Imports
	extern "C" system::PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
	extern "C" PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
	extern "C" PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
}

namespace memory
{
	// Imports
	extern "C" NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
	extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
}