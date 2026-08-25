#pragma once
#include <includes/includes.hxx>
#include <ntddscsi.h>
#include <nvme.h>
#include <ata.h>
#include <scsi.h>
#include <ntdddisk.h>

namespace i_definitions {

#define IOCTL_DEVICE L"\\Device\\iamsour"
#define IOCTL_SYMBOLIC_LINK L"\\DosDevices\\iamsour"

	inline UNICODE_STRING i_device = { 0 };
	inline UNICODE_STRING i_symbolic = { 0 };
}

namespace i_s_globals {
	inline ULONG global_seed = 0x50A400;
}

namespace i_control {
#define SPOOF_DISK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SPOOF_BIOS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SPOOF_NETWORK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SPOOF_BOARD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define UNLOAD_DEVICE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
}

namespace i_structures {
	typedef struct _DISK_REQUEST
	{
		CHAR SerialNumber[256];
		BOOLEAN IsNull;
		CHAR Model[256];
		CHAR Vendor[256];
	} DISK_REQUEST, * PDISK_REQUEST;

	typedef struct _BIOS_REQUEST
	{
		CHAR SerialNumber[256];
		BOOLEAN IsNull;
		CHAR Version[256];
		CHAR Vendor[256];
	} BIOS_REQUEST, * PBIOS_REQUEST;

	typedef struct _NETWORK_REQUEST
	{
		CHAR MacAddress[18];
		BOOLEAN IsNull;
	} NETWORK_REQUEST, * PNETWORK_REQUEST;

	typedef struct _BOARD_REQUEST
	{
		CHAR SerialNumber[256];
		BOOLEAN IsNull;
		CHAR Model[256];
		CHAR Vendor[256];
	} BOARD_REQUEST, * PBOARD_REQUEST;

	typedef struct _UNLOAD_REQUEST
	{
		BOOLEAN Confirm;
	} UNLOAD_REQUEST, * PUNLOAD_REQUEST;
}

namespace d_definitions {
	inline PDEVICE_OBJECT i_device_object;
	inline PDRIVER_OBJECT i_driver_object;
}

namespace e_structures {
	template <typename T>
	struct s_entries
	{
		T g_Original{};
		T g_Modified{};
		bool InUse = false;
	};

	enum pe_magic_t {
		dos_header = 0x5a4d,
		nt_headers = 0x4550,
		opt_header = 0x020b
	};

	struct section_header_t {
		char m_name[0x8];
		union {
			std::int32_t m_physical_address;
			std::int32_t m_virtual_size;
		};
		std::int32_t m_virtual_address;
		std::int32_t m_size_of_raw_data;
		std::int32_t m_pointer_to_raw_data;
		std::int32_t m_pointer_to_relocations;
		std::int32_t m_pointer_to_line_numbers;
		std::int16_t m_number_of_relocations;
		std::int16_t m_number_of_line_numbers;
		std::int32_t m_characteristics;
	};

	struct hook_state_t {
		std::uint8_t original_bytes[64]{ };
		size_t hook_size{ };
		std::uint64_t trampoline{ };
	};

	struct virt_addr_t {
		std::uint64_t value;
		std::uint64_t offset;
		std::uint64_t pte_index;
		std::uint64_t pde_index;
		std::uint64_t pdpte_index;
		std::uint64_t pml4e_index;

		virt_addr_t(std::uint64_t addr) : value(addr) {
			offset = addr & 0xFFF;
			pte_index = (addr >> 12) & 0x1FF;
			pde_index = (addr >> 21) & 0x1FF;
			pdpte_index = (addr >> 30) & 0x1FF;
			pml4e_index = (addr >> 39) & 0x1FF;
		}

		virt_addr_t() : value(0), offset(0), pte_index(0), pde_index(0), pdpte_index(0), pml4e_index(0) {}
	};

	struct mi_active_pfn_t {
		std::uint64_t m_page_frame : 40;
		std::uint64_t m_priority : 8;
		std::uint64_t m_color : 16;
	};

	struct mmpte_hardware_t {
		std::uint64_t m_valid : 1;
		std::uint64_t m_write : 1;
		std::uint64_t m_owner : 1;
		std::uint64_t m_write_through : 1;
		std::uint64_t m_cache_disable : 1;
		std::uint64_t m_accessed : 1;
		std::uint64_t m_dirty : 1;
		std::uint64_t m_large_page : 1;
		std::uint64_t m_global : 1;
		std::uint64_t m_copy_on_write : 1;
		std::uint64_t m_prototype : 1;
		std::uint64_t m_reserved0 : 1;
		std::uint64_t m_page_frame_number : 36;
		std::uint64_t m_reserved1 : 4;
		std::uint64_t m_software_ws_index : 11;
		std::uint64_t m_no_execute : 1;
	};

	struct mmpte_t {
		union {
			mmpte_hardware_t m_hard;
			std::uint64_t m_value;
		};
	};

	struct mipfnblink_t {
		union {
			std::uint64_t m_blink : 40;
			std::uint64_t m_type_size : 24;
		};
	};

	struct mi_pfn_ulong5_t {
		union {
			struct {
				std::uint32_t m_modified_write_count : 16;
				std::uint32_t m_shared_count : 16;
			};
			std::uint32_t m_entire_field;
		};
	};

	struct mmpfnentry1_t {
		std::uint8_t m_page_color : 6;
		std::uint8_t m_modified : 1;
		std::uint8_t m_read_in_progress : 1;
	};

	struct mmpfnentry3_t {
		std::uint8_t priority : 3;
		std::uint8_t on_protected_standby : 1;
		std::uint8_t in_page_error : 1;
		std::uint8_t system_charged_page : 1;
		std::uint8_t removal_requested : 1;
		std::uint8_t parity_error : 1;
	};

	typedef union _pte {
		struct {
			std::uint64_t present : 1;                   // Must be 1 if valid
			std::uint64_t read_write : 1;               // Write access control
			std::uint64_t user_supervisor : 1;           // User/supervisor access control
			std::uint64_t page_write_through : 1;        // Write-through caching
			std::uint64_t cached_disable : 1;            // Cache disable
			std::uint64_t accessed : 1;                  // Set when accessed
			std::uint64_t dirty : 1;                    // Set when written to
			std::uint64_t pat : 1;                      // Page Attribute Table bit
			std::uint64_t global : 1;                   // Global page
			std::uint64_t ignored1 : 3;                 // Ignored
			std::uint64_t pfn : 36;                     // Physical frame number
			std::uint64_t reserved : 4;                 // Reserved for software
			std::uint64_t ignored2 : 7;                 // Ignored
			std::uint64_t protection_key : 4;           // Protection key
			std::uint64_t no_execute : 1;               // No-execute bit
		} hard;
		std::uint64_t value;
	} pte, * ppte;

	typedef union _pml4e {
		struct {
			std::uint64_t present : 1;                   // Must be 1 if valid
			std::uint64_t read_write : 1;               // Write access control
			std::uint64_t user_supervisor : 1;           // User/supervisor access control
			std::uint64_t page_write_through : 1;        // Write-through caching
			std::uint64_t cached_disable : 1;            // Cache disable
			std::uint64_t accessed : 1;                  // Set when accessed
			std::uint64_t ignored0 : 1;                  // Ignored
			std::uint64_t large_page : 1;               // Reserved (must be 0)
			std::uint64_t ignored1 : 4;                 // Ignored
			std::uint64_t pfn : 36;                     // Physical frame number
			std::uint64_t reserved : 4;                 // Reserved for software
			std::uint64_t ignored2 : 11;                // Ignored
			std::uint64_t no_execute : 1;               // No-execute bit
		} hard;
		std::uint64_t value;
	} pml4e, * ppml4e;

	typedef union _pdpte {
		struct {
			std::uint64_t present : 1;                   // Must be 1 if valid
			std::uint64_t read_write : 1;               // Write access control
			std::uint64_t user_supervisor : 1;           // User/supervisor access control
			std::uint64_t page_write_through : 1;        // Write-through caching
			std::uint64_t cached_disable : 1;            // Cache disable
			std::uint64_t accessed : 1;                  // Set when accessed
			std::uint64_t dirty : 1;                    // Set when written to (1GB pages)
			std::uint64_t page_size : 1;                // 1=1GB page, 0=points to page directory
			std::uint64_t ignored1 : 4;                 // Ignored
			std::uint64_t pfn : 36;                     // Physical frame number
			std::uint64_t reserved : 4;                 // Reserved for software
			std::uint64_t ignored2 : 11;                // Ignored
			std::uint64_t no_execute : 1;               // No-execute bit
		} hard;
		std::uint64_t value;
	} pdpte, * ppdpte;

	typedef union _pde {
		struct {
			std::uint64_t present : 1;                   // Must be 1 if valid
			std::uint64_t read_write : 1;               // Write access control
			std::uint64_t user_supervisor : 1;           // User/supervisor access control
			std::uint64_t page_write_through : 1;        // Write-through caching
			std::uint64_t cached_disable : 1;            // Cache disable
			std::uint64_t accessed : 1;                  // Set when accessed
			std::uint64_t dirty : 1;                    // Set when written to (2MB pages)
			std::uint64_t page_size : 1;                // 1=2MB page, 0=points to page table
			std::uint64_t global : 1;                   // Global page (if CR4.PGE=1)
			std::uint64_t ignored1 : 3;                 // Ignored
			std::uint64_t pfn : 36;                     // Physical frame number
			std::uint64_t reserved : 4;                 // Reserved for software
			std::uint64_t ignored2 : 11;                // Ignored
			std::uint64_t no_execute : 1;               // No-execute bit
		} hard;
		std::uint64_t value;
	} pde, * ppde;

	typedef union
	{
		struct
		{
			UINT64 VirtualModeExtensions : 1;
#define CR4_VIRTUAL_MODE_EXTENSIONS_BIT                              0
#define CR4_VIRTUAL_MODE_EXTENSIONS_FLAG                             0x01
#define CR4_VIRTUAL_MODE_EXTENSIONS_MASK                             0x01
#define CR4_VIRTUAL_MODE_EXTENSIONS(_)                               (((_) >> 0) & 0x01)
			UINT64 ProtectedModeVirtualInterrupts : 1;
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_BIT                    1
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_FLAG                   0x02
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_MASK                   0x01
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS(_)                     (((_) >> 1) & 0x01)
			UINT64 TimestampDisable : 1;
#define CR4_TIMESTAMP_DISABLE_BIT                                    2
#define CR4_TIMESTAMP_DISABLE_FLAG                                   0x04
#define CR4_TIMESTAMP_DISABLE_MASK                                   0x01
#define CR4_TIMESTAMP_DISABLE(_)                                     (((_) >> 2) & 0x01)
			UINT64 DebuggingExtensions : 1;
#define CR4_DEBUGGING_EXTENSIONS_BIT                                 3
#define CR4_DEBUGGING_EXTENSIONS_FLAG                                0x08
#define CR4_DEBUGGING_EXTENSIONS_MASK                                0x01
#define CR4_DEBUGGING_EXTENSIONS(_)                                  (((_) >> 3) & 0x01)
			UINT64 PageSizeExtensions : 1;
#define CR4_PAGE_SIZE_EXTENSIONS_BIT                                 4
#define CR4_PAGE_SIZE_EXTENSIONS_FLAG                                0x10
#define CR4_PAGE_SIZE_EXTENSIONS_MASK                                0x01
#define CR4_PAGE_SIZE_EXTENSIONS(_)                                  (((_) >> 4) & 0x01)
			UINT64 PhysicalAddressExtension : 1;
#define CR4_PHYSICAL_ADDRESS_EXTENSION_BIT                           5
#define CR4_PHYSICAL_ADDRESS_EXTENSION_FLAG                          0x20
#define CR4_PHYSICAL_ADDRESS_EXTENSION_MASK                          0x01
#define CR4_PHYSICAL_ADDRESS_EXTENSION(_)                            (((_) >> 5) & 0x01)
			UINT64 MachineCheckEnable : 1;
#define CR4_MACHINE_CHECK_ENABLE_BIT                                 6
#define CR4_MACHINE_CHECK_ENABLE_FLAG                                0x40
#define CR4_MACHINE_CHECK_ENABLE_MASK                                0x01
#define CR4_MACHINE_CHECK_ENABLE(_)                                  (((_) >> 6) & 0x01)
			UINT64 PageGlobalEnable : 1;
#define CR4_PAGE_GLOBAL_ENABLE_BIT                                   7
#define CR4_PAGE_GLOBAL_ENABLE_FLAG                                  0x80
#define CR4_PAGE_GLOBAL_ENABLE_MASK                                  0x01
#define CR4_PAGE_GLOBAL_ENABLE(_)                                    (((_) >> 7) & 0x01)
			UINT64 PerformanceMonitoringCounterEnable : 1;
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_BIT                8
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_FLAG               0x100
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_MASK               0x01
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE(_)                 (((_) >> 8) & 0x01)
			UINT64 OsFxsaveFxrstorSupport : 1;
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_BIT                            9
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_FLAG                           0x200
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_MASK                           0x01
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT(_)                             (((_) >> 9) & 0x01)
			UINT64 OsXmmExceptionSupport : 1;
#define CR4_OS_XMM_EXCEPTION_SUPPORT_BIT                             10
#define CR4_OS_XMM_EXCEPTION_SUPPORT_FLAG                            0x400
#define CR4_OS_XMM_EXCEPTION_SUPPORT_MASK                            0x01
#define CR4_OS_XMM_EXCEPTION_SUPPORT(_)                              (((_) >> 10) & 0x01)
			UINT64 UsermodeInstructionPrevention : 1;
#define CR4_USERMODE_INSTRUCTION_PREVENTION_BIT                      11
#define CR4_USERMODE_INSTRUCTION_PREVENTION_FLAG                     0x800
#define CR4_USERMODE_INSTRUCTION_PREVENTION_MASK                     0x01
#define CR4_USERMODE_INSTRUCTION_PREVENTION(_)                       (((_) >> 11) & 0x01)
			UINT64 Reserved1 : 1;
			UINT64 VmxEnable : 1;
#define CR4_VMX_ENABLE_BIT                                           13
#define CR4_VMX_ENABLE_FLAG                                          0x2000
#define CR4_VMX_ENABLE_MASK                                          0x01
#define CR4_VMX_ENABLE(_)                                            (((_) >> 13) & 0x01)
			UINT64 SmxEnable : 1;
#define CR4_SMX_ENABLE_BIT                                           14
#define CR4_SMX_ENABLE_FLAG                                          0x4000
#define CR4_SMX_ENABLE_MASK                                          0x01
#define CR4_SMX_ENABLE(_)                                            (((_) >> 14) & 0x01)
			UINT64 Reserved2 : 1;
			UINT64 FsgsbaseEnable : 1;
#define CR4_FSGSBASE_ENABLE_BIT                                      16
#define CR4_FSGSBASE_ENABLE_FLAG                                     0x10000
#define CR4_FSGSBASE_ENABLE_MASK                                     0x01
#define CR4_FSGSBASE_ENABLE(_)                                       (((_) >> 16) & 0x01)
			UINT64 PcidEnable : 1;
#define CR4_PCID_ENABLE_BIT                                          17
#define CR4_PCID_ENABLE_FLAG                                         0x20000
#define CR4_PCID_ENABLE_MASK                                         0x01
#define CR4_PCID_ENABLE(_)                                           (((_) >> 17) & 0x01)
			UINT64 OsXsave : 1;
#define CR4_OS_XSAVE_BIT                                             18
#define CR4_OS_XSAVE_FLAG                                            0x40000
#define CR4_OS_XSAVE_MASK                                            0x01
#define CR4_OS_XSAVE(_)                                              (((_) >> 18) & 0x01)
			UINT64 Reserved3 : 1;
			UINT64 SmepEnable : 1;
#define CR4_SMEP_ENABLE_BIT                                          20
#define CR4_SMEP_ENABLE_FLAG                                         0x100000
#define CR4_SMEP_ENABLE_MASK                                         0x01
#define CR4_SMEP_ENABLE(_)                                           (((_) >> 20) & 0x01)
			UINT64 SmapEnable : 1;
#define CR4_SMAP_ENABLE_BIT                                          21
#define CR4_SMAP_ENABLE_FLAG                                         0x200000
#define CR4_SMAP_ENABLE_MASK                                         0x01
#define CR4_SMAP_ENABLE(_)                                           (((_) >> 21) & 0x01)
			UINT64 ProtectionKeyEnable : 1;
#define CR4_PROTECTION_KEY_ENABLE_BIT                                22
#define CR4_PROTECTION_KEY_ENABLE_FLAG                               0x400000
#define CR4_PROTECTION_KEY_ENABLE_MASK                               0x01
#define CR4_PROTECTION_KEY_ENABLE(_)                                 (((_) >> 22) & 0x01)
			UINT64 CETEnabled : 1;
			UINT64 PKSEnabled : 1;
			UINT64 Reserved4 : 39;
		};
		UINT64 Flags;
	} CR4;

	typedef union
	{
		struct
		{
			UINT64 ProtectionEnable : 1;
#define CR0_PROTECTION_ENABLE_BIT                                    0
#define CR0_PROTECTION_ENABLE_FLAG                                   0x01
#define CR0_PROTECTION_ENABLE_MASK                                   0x01
#define CR0_PROTECTION_ENABLE(_)                                     (((_) >> 0) & 0x01)
			UINT64 MonitorCoprocessor : 1;
#define CR0_MONITOR_COPROCESSOR_BIT                                  1
#define CR0_MONITOR_COPROCESSOR_FLAG                                 0x02
#define CR0_MONITOR_COPROCESSOR_MASK                                 0x01
#define CR0_MONITOR_COPROCESSOR(_)                                   (((_) >> 1) & 0x01)
			UINT64 EmulateFpu : 1;
#define CR0_EMULATE_FPU_BIT                                          2
#define CR0_EMULATE_FPU_FLAG                                         0x04
#define CR0_EMULATE_FPU_MASK                                         0x01
#define CR0_EMULATE_FPU(_)                                           (((_) >> 2) & 0x01)
			UINT64 TaskSwitched : 1;
#define CR0_TASK_SWITCHED_BIT                                        3
#define CR0_TASK_SWITCHED_FLAG                                       0x08
#define CR0_TASK_SWITCHED_MASK                                       0x01
#define CR0_TASK_SWITCHED(_)                                         (((_) >> 3) & 0x01)
			UINT64 ExtensionType : 1;
#define CR0_EXTENSION_TYPE_BIT                                       4
#define CR0_EXTENSION_TYPE_FLAG                                      0x10
#define CR0_EXTENSION_TYPE_MASK                                      0x01
#define CR0_EXTENSION_TYPE(_)                                        (((_) >> 4) & 0x01)
			UINT64 NumericError : 1;
#define CR0_NUMERIC_ERROR_BIT                                        5
#define CR0_NUMERIC_ERROR_FLAG                                       0x20
#define CR0_NUMERIC_ERROR_MASK                                       0x01
#define CR0_NUMERIC_ERROR(_)                                         (((_) >> 5) & 0x01)
			UINT64 Reserved1 : 10;
			UINT64 WriteProtect : 1;
#define CR0_WRITE_PROTECT_BIT                                        16
#define CR0_WRITE_PROTECT_FLAG                                       0x10000
#define CR0_WRITE_PROTECT_MASK                                       0x01
#define CR0_WRITE_PROTECT(_)                                         (((_) >> 16) & 0x01)
			UINT64 Reserved2 : 1;
			UINT64 AlignmentMask : 1;
#define CR0_ALIGNMENT_MASK_BIT                                       18
#define CR0_ALIGNMENT_MASK_FLAG                                      0x40000
#define CR0_ALIGNMENT_MASK_MASK                                      0x01
#define CR0_ALIGNMENT_MASK(_)                                        (((_) >> 18) & 0x01)
			UINT64 Reserved3 : 10;
			UINT64 NotWriteThrough : 1;
#define CR0_NOT_WRITE_THROUGH_BIT                                    29
#define CR0_NOT_WRITE_THROUGH_FLAG                                   0x20000000
#define CR0_NOT_WRITE_THROUGH_MASK                                   0x01
#define CR0_NOT_WRITE_THROUGH(_)                                     (((_) >> 29) & 0x01)
			UINT64 CacheDisable : 1;
#define CR0_CACHE_DISABLE_BIT                                        30
#define CR0_CACHE_DISABLE_FLAG                                       0x40000000
#define CR0_CACHE_DISABLE_MASK                                       0x01
#define CR0_CACHE_DISABLE(_)                                         (((_) >> 30) & 0x01)
			UINT64 PagingEnable : 1;
#define CR0_PAGING_ENABLE_BIT                                        31
#define CR0_PAGING_ENABLE_FLAG                                       0x80000000
#define CR0_PAGING_ENABLE_MASK                                       0x01
#define CR0_PAGING_ENABLE(_)                                         (((_) >> 31) & 0x01)
			UINT64 Reserved4 : 32;
		};
		UINT64 Flags;
	} CR0;

	struct nvme_id_power_state {
		unsigned short  max_power; // centiwatts
		unsigned char   rsvd2;
		unsigned char   flags;
		unsigned int    entry_lat; // microseconds
		unsigned int    exit_lat;  // microseconds
		unsigned char   read_tput;
		unsigned char   read_lat;
		unsigned char   write_tput;
		unsigned char   write_lat;
		unsigned short  idle_power;
		unsigned char   idle_scale;
		unsigned char   rsvd19;
		unsigned short  active_power;
		unsigned char   active_work_scale;
		unsigned char   rsvd23[9];
	};

	struct nvme_id_ctrl {
		unsigned short  vid;
		unsigned short  ssvid;
		char            sn[20];
		char            mn[40];
		char            fr[8];
		unsigned char   rab;
		unsigned char   ieee[3];
		unsigned char   cmic;
		unsigned char   mdts;
		unsigned short  cntlid;
		unsigned int    ver;
		unsigned int    rtd3r;
		unsigned int    rtd3e;
		unsigned int    oaes;
		unsigned int    ctratt;
		unsigned char   rsvd100[156];
		unsigned short  oacs;
		unsigned char   acl;
		unsigned char   aerl;
		unsigned char   frmw;
		unsigned char   lpa;
		unsigned char   elpe;
		unsigned char   npss;
		unsigned char   avscc;
		unsigned char   apsta;
		unsigned short  wctemp;
		unsigned short  cctemp;
		unsigned short  mtfa;
		unsigned int    hmpre;
		unsigned int    hmmin;
		unsigned char   tnvmcap[16];
		unsigned char   unvmcap[16];
		unsigned int    rpmbs;
		unsigned short  edstt;
		unsigned char   dsto;
		unsigned char   fwug;
		unsigned short  kas;
		unsigned short  hctma;
		unsigned short  mntmt;
		unsigned short  mxtmt;
		unsigned int    sanicap;
		unsigned char   rsvd332[180];
		unsigned char   sqes;
		unsigned char   cqes;
		unsigned short  maxcmd;
		unsigned int    nn;
		unsigned short  oncs;
		unsigned short  fuses;
		unsigned char   fna;
		unsigned char   vwc;
		unsigned short  awun;
		unsigned short  awupf;
		unsigned char   nvscc;
		unsigned char   rsvd531;
		unsigned short  acwu;
		unsigned char   rsvd534[2];
		unsigned int    sgls;
		unsigned char   rsvd540[228];
		char			      subnqn[256];
		unsigned char   rsvd1024[768];
		unsigned int    ioccsz;
		unsigned int    iorcsz;
		unsigned short  icdoff;
		unsigned char   ctrattr;
		unsigned char   msdbd;
		unsigned char   rsvd1804[244];
		struct nvme_id_power_state  psd[32];
		unsigned char   vs[1024];
	};

#define SPT_CDB_LENGTH 32
#define SPT_SENSE_LENGTH 32
#define SPTWB_DATA_LENGTH 512

#define NVME_STORPORT_DRIVER 0xe000
#define NVME_PASS_THROUGH_SRB_IO_CODE \
CTL_CODE(NVME_STORPORT_DRIVER, 0x0800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTEL_NVME_PASS_THROUGH CTL_CODE(0xf000, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)

	typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS24 {
		SCSI_PASS_THROUGH Spt;
		UCHAR             SenseBuf[24];
		UCHAR             DataBuf[4096];
	} SCSI_PASS_THROUGH_WITH_BUFFERS24, * PSCSI_PASS_THROUGH_WITH_BUFFERS24;

	typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS {
		SCSI_PASS_THROUGH Spt;
		ULONG             Filler;      // realign buffers to double word boundary
		UCHAR             SenseBuf[32];
		UCHAR             DataBuf[4096];
	} SCSI_PASS_THROUGH_WITH_BUFFERS, * PSCSI_PASS_THROUGH_WITH_BUFFERS;

	typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS_EX {
		SCSI_PASS_THROUGH_EX Spt;
		UCHAR             ucCdbBuf[SPT_CDB_LENGTH - 1];       // cushion for spt.Cdb
		ULONG             Filler;      // realign buffers to double word boundary
		STOR_ADDR_BTL8    StorAddress;
		UCHAR             ucSenseBuf[SPT_SENSE_LENGTH];
		UCHAR             ucDataBuf[SPTWB_DATA_LENGTH];     // buffer for DataIn or DataOut
	} SCSI_PASS_THROUGH_WITH_BUFFERS_EX, * PSCSI_PASS_THROUGH_WITH_BUFFERS_EX;

	typedef union
	{
		struct
		{
			ULONG Opcode : 8;
			ULONG FUSE : 2;
			ULONG _Rsvd : 4;
			ULONG PSDT : 2;
			ULONG CID : 16;
		} DUMMYSTRUCTNAME;
		ULONG AsDWord;
	} NVME_CDW0, * PNVME_CDW0;

	// NVMe Command Format

	// See NVMe specification 1.3c Section 4.2, Figure 10

	typedef union
	{
		struct
		{
			ULONG   CNS : 2;
			ULONG   _Rsvd : 30;
		} DUMMYSTRUCTNAME;
		ULONG AsDWord;
	} NVME_IDENTIFY_CDW10, * PNVME_IDENTIFY_CDW10;

	// NVMe Specification < 1.3

	typedef union
	{
		struct
		{
			ULONG   LID : 8;
			ULONG   _Rsvd1 : 8;
			ULONG   NUMD : 12;
			ULONG   _Rsvd2 : 4;
		} DUMMYSTRUCTNAME;
		ULONG   AsDWord;
	} NVME_GET_LOG_PAGE_CDW10, * PNVME_GET_LOG_PAGE_CDW10;

	// NVMe Specification >= 1.3

	typedef union
	{
		struct
		{
			ULONG   LID : 8;
			ULONG   LSP : 4;
			ULONG   Reserved0 : 3;
			ULONG   RAE : 1;
			ULONG   NUMDL : 16;
		} DUMMYSTRUCTNAME;
		ULONG   AsDWord;
	} NVME_GET_LOG_PAGE_CDW10_V13, * PNVME_GET_LOG_PAGE_CDW10_V13;

	typedef struct
	{
		// Common fields for all commands
		NVME_CDW0           CDW0;
		ULONG               NSID;
		ULONG               _Rsvd[2];
		ULONGLONG           MPTR;
		ULONGLONG           PRP1;
		ULONGLONG           PRP2;
		// Command independent fields from CDW10 to CDW15
		union
		{
			// Admin Command: Identify (6)
			struct
			{
				NVME_IDENTIFY_CDW10 CDW10;
				ULONG   CDW11;
				ULONG   CDW12;
				ULONG   CDW13;
				ULONG   CDW14;
				ULONG   CDW15;
			} IDENTIFY;
			// Admin Command: Get Log Page (2)
			struct
			{
				NVME_GET_LOG_PAGE_CDW10 CDW10;
				//NVME_GET_LOG_PAGE_CDW10_V13 CDW10;
				ULONG   CDW11;
				ULONG   CDW12;
				ULONG   CDW13;
				ULONG   CDW14;
				ULONG   CDW15;
			} GET_LOG_PAGE;
		} u;
	} NVME_CMD, * PNVME_CMD;

	typedef union _STORAGE_DEVICE_DESCRIPTOR_DATA {
		STORAGE_DEVICE_DESCRIPTOR desc;
		char raw[256];
	} STORAGE_DEVICE_DESCRIPTOR_DATA, * PSTORAGE_DEVICE_DESCRIPTOR_DATA;

	typedef struct _WWN {
		USHORT WorldWideName[4];
		USHORT ReservedForWorldWideName128[4];
	} WWN, * PWWN;

	struct NVME_IDENTIFY_DEVICE
	{
		CHAR		Reserved1[4];
		CHAR		SerialNumber[20];
		CHAR		Model[40];
		CHAR		FirmwareRev[8];
		CHAR		Reserved2[9];
		CHAR		MinorVersion;
		SHORT		MajorVersion;
		CHAR		Reserved3[428];
		CHAR		Reserved4[3584];
	};

#pragma pack(push,1)

	typedef struct {
		uint8_t len;
		uint8_t p_rep;
		uint8_t p_lock;
		uint8_t p_seg;
		uint8_t p_66;
		uint8_t p_67;
		uint8_t rex;
		uint8_t rex_w;
		uint8_t rex_r;
		uint8_t rex_x;
		uint8_t rex_b;
		uint8_t opcode;
		uint8_t opcode2;
		uint8_t modrm;
		uint8_t modrm_mod;
		uint8_t modrm_reg;
		uint8_t modrm_rm;
		uint8_t sib;
		uint8_t sib_scale;
		uint8_t sib_index;
		uint8_t sib_base;
		union {
			uint8_t imm8;
			uint16_t imm16;
			uint32_t imm32;
			uint64_t imm64;
		} imm;
		union {
			uint8_t disp8;
			uint16_t disp16;
			uint32_t disp32;
		} disp;
		uint32_t flags;
	} hde64s;

#pragma pack(pop)

	typedef struct {
		ATA_PASS_THROUGH_EX apt;
		ULONG Filler;
		UCHAR ucDataBuf[32 * 512];
	} ATA_PASS_THROUGH_EX_WITH_BUFFERS;

	typedef struct _STORAGE_PROTOCOL_SPECIFIC_QUERY_WITH_BUFFER {
		STORAGE_PROPERTY_QUERY Query;
		STORAGE_PROTOCOL_SPECIFIC_DATA ProtocolData;
		UCHAR DataBuffer[4096]; // NVMe identify data size
	} STORAGE_PROTOCOL_SPECIFIC_QUERY_WITH_BUFFER;

	struct ata_identify_device {
		unsigned short words000_009[10];
		unsigned char  serial_no[20];
		unsigned short words020_022[3];
		unsigned char  fw_rev[8];
		unsigned char  model[40];
		unsigned short words047_079[33];
		unsigned short major_rev_num;
		unsigned short minor_rev_num;
		unsigned short command_set_1;
		unsigned short command_set_2;
		unsigned short command_set_extension;
		unsigned short cfs_enable_1;
		unsigned short word086;
		unsigned short csf_default;
		unsigned short words088_255[168];
	};

	struct page_mapping_t {
		std::uint64_t m_virtual_address;
		pte* m_pte_address;
		std::uint64_t m_original_pfn;
	};

	typedef struct _IDINFO
	{
		USHORT	wGenConfig;
		USHORT	wNumCyls;
		USHORT	wReserved;
		USHORT	wNumHeads;
		USHORT	wBytesPerTrack;
		USHORT	wBytesPerSector;
		USHORT	wNumSectorsPerTrack;
		USHORT	wVendorUnique[3];
		CHAR	sSerialNumber[20];
		USHORT	wBufferType;
		USHORT	wBufferSize;
		USHORT	wECCSize;
		CHAR	sFirmwareRev[8];
		CHAR	sModelNumber[40];
		USHORT	wMoreVendorUnique;
		USHORT	wDoubleWordIO;
		struct {
			USHORT	Reserved : 8;
			USHORT	DMA : 1;
			USHORT	LBA : 1;
			USHORT	DisIORDY : 1;
			USHORT	IORDY : 1;
			USHORT	SoftReset : 1;
			USHORT	Overlap : 1;
			USHORT	Queue : 1;
			USHORT	InlDMA : 1;
		} wCapabilities;
		USHORT	wReserved1;
		USHORT	wPIOTiming;
		USHORT	wDMATiming;
		struct {
			USHORT	CHSNumber : 1;
			USHORT	CycleNumber : 1;
			USHORT	UnltraDMA : 1;
			USHORT	Reserved : 13;
		} wFieldValidity;
		USHORT	wNumCurCyls;
		USHORT	wNumCurHeads;
		USHORT	wNumCurSectorsPerTrack;
		USHORT	wCurSectorsLow;
		USHORT	wCurSectorsHigh;
		struct {
			USHORT	CurNumber : 8;
			USHORT	Multi : 1;
			USHORT	Reserved : 7;
		} wMultSectorStuff;
		ULONG	dwTotalSectors;
		USHORT	wSingleWordDMA;
		struct {
			USHORT	Mode0 : 1;
			USHORT	Mode1 : 1;
			USHORT	Mode2 : 1;
			USHORT	Reserved1 : 5;
			USHORT	Mode0Sel : 1;
			USHORT	Mode1Sel : 1;
			USHORT	Mode2Sel : 1;
			USHORT	Reserved2 : 5;
		} wMultiWordDMA;
		struct {
			USHORT	AdvPOIModes : 8;
			USHORT	Reserved : 8;
		} wPIOCapacity;
		USHORT	wMinMultiWordDMACycle;
		USHORT	wRecMultiWordDMACycle;
		USHORT	wMinPIONoFlowCycle;
		USHORT	wMinPOIFlowCycle;
		USHORT	wReserved69[11];
		struct {
			USHORT	Reserved1 : 1;
			USHORT	ATA1 : 1;
			USHORT	ATA2 : 1;
			USHORT	ATA3 : 1;
			USHORT	ATA4 : 1;
			USHORT	ATA5 : 1;
			USHORT	ATA6 : 1;
			USHORT	ATA7 : 1;
			USHORT	ATA8 : 1;
			USHORT	ATA9 : 1;
			USHORT	ATA10 : 1;
			USHORT	ATA11 : 1;
			USHORT	ATA12 : 1;
			USHORT	ATA13 : 1;
			USHORT	ATA14 : 1;
			USHORT	Reserved2 : 1;
		} wMajorVersion;
		USHORT	wMinorVersion;
		USHORT	wReserved82[6];
		struct {
			USHORT	Mode0 : 1;
			USHORT	Mode1 : 1;
			USHORT	Mode2 : 1;
			USHORT	Mode3 : 1;
			USHORT	Mode4 : 1;
			USHORT	Mode5 : 1;
			USHORT	Mode6 : 1;
			USHORT	Mode7 : 1;
			USHORT	Mode0Sel : 1;
			USHORT	Mode1Sel : 1;
			USHORT	Mode2Sel : 1;
			USHORT	Mode3Sel : 1;
			USHORT	Mode4Sel : 1;
			USHORT	Mode5Sel : 1;
			USHORT	Mode6Sel : 1;
			USHORT	Mode7Sel : 1;
		} wUltraDMA;
		USHORT	wReserved89[167];
	} IDINFO, * PIDINFO;

	struct mmpfn_t {
		union {
			LIST_ENTRY m_list_entry;
			RTL_BALANCED_NODE m_tree_node;
			struct {
				union {
					union {
					    SINGLE_LIST_ENTRY m_next_slist_pfn;
						void* m_next;
						struct {
							std::uint64_t m_flink : 40;
							std::uint64_t m_node_flink_low : 24;
						};
						mi_active_pfn_t m_active;
					} m_u1;

					union {
						mmpte_t* m_pte_address;
						std::uint64_t m_pte_long;
					};

					mmpte_t m_original_pte;
				};
			};
		};

		mipfnblink_t m_u2;

		union {
			union {
				struct {
					std::uint16_t m_reference_count;
					mmpfnentry1_t m_e1;
					mmpfnentry3_t m_e3;
				};
				struct {
					std::uint16_t m_reference_count2;
				} m_e2;
				struct {
					std::uint32_t m_entire_field;
				} m_e4;
			};
		} m_u3;

		mi_pfn_ulong5_t m_u5;

		union {
			union {
				struct {
					std::uint64_t m_pte_frame : 40;
					std::uint64_t m_resident_page : 1;
					std::uint64_t m_unused1 : 1;
					std::uint64_t m_unused2 : 1;
					std::uint64_t m_partition : 10;
					std::uint64_t m_file_only : 1;
					std::uint64_t m_pfn_exists : 1;
					std::uint64_t m_node_flink_high : 5;
					std::uint64_t m_page_identity : 3;
					std::uint64_t m_prototype_pte : 1;
				};
				std::uint64_t m_entire_field;
			};
		} m_u4;
	};

	struct mmsupport_t {
		LIST_ENTRY m_work_set_exp_head;                   // +0x000
		std::uint64_t m_flags;                              // +0x010
		std::uint64_t m_last_trim_time;                     // +0x018
		union {
			std::uint64_t m_page_fault_count;
			std::uint64_t m_peak_virtual_size;
			std::uint64_t m_virtual_size;
		};                                                  // +0x020
		std::uint64_t m_min_ws_size;                       // +0x028
		std::uint64_t m_max_ws_size;                       // +0x030
		std::uint64_t m_virtual_memory_threshold;          // +0x038
		std::uint64_t m_working_set_size;                  // +0x040
		std::uint64_t m_peak_working_set_size;            // +0x048
	};

	struct kprocess_t {
	    DISPATCHER_HEADER m_header;                       // +0x000
		LIST_ENTRY m_profile_list_head;                  // +0x018
		std::uint64_t m_directory_table_base;              // +0x028
		LIST_ENTRY m_thread_list_head;                   // +0x030
		std::uint64_t m_flags2;                            // +0x038
		std::uint64_t m_session_id;                        // +0x040
		mmsupport_t m_mm;                                  // +0x048
		LIST_ENTRY m_process_list_entry;                 // +0x0E0
		std::uint64_t m_total_cycle_time;                  // +0x0F0
		std::uint64_t m_create_time;                       // +0x0F8
		std::uint64_t m_user_time;                         // +0x100
		std::uint64_t m_kernel_time;                       // +0x108
		LIST_ENTRY m_active_process_links;               // +0x110
		std::uint64_t m_process_quota_usage[2];            // +0x120
		std::uint64_t m_process_quota_peak[2];             // +0x130
		std::uint64_t m_commit_charge;                     // +0x140
		std::uint64_t m_peak_commit_charge;                // +0x148
		std::uint64_t m_peak_virtual_size;                 // +0x150
		std::uint64_t m_virtual_size;                      // +0x158
		std::uint32_t m_exit_status;                       // +0x160
		std::uint32_t m_address_policy;                    // +0x164
	};

	struct se_audit_process_creation_info_t {
		UNICODE_STRING* m_image_file_name;    // Pointer to UNICODE_STRING
	};

	struct ex_fast_ref_t {
		union {
			void* m_object;
			std::uint64_t m_ref_cnt : 4;
			std::uint64_t m_value;
		};
	}; // Size: 0x8

	struct eprocess_t {
		kprocess_t m_pcb;                                                     // +0x000
		EX_PUSH_LOCK m_process_lock;                                       // +0x438
		void* m_unique_process_id;                                           // +0x440
		LIST_ENTRY m_active_process_links;                                // +0x448
		EX_RUNDOWN_REF m_rundown_protect;                                 // +0x458

		union {
			std::uint32_t m_flags2;                                         // +0x460
			struct {
				std::uint32_t m_job_not_really_active : 1;
				std::uint32_t m_accounting_folded : 1;
				std::uint32_t m_new_process_reported : 1;
				std::uint32_t m_exit_process_reported : 1;
				std::uint32_t m_report_commit_changes : 1;
				std::uint32_t m_last_report_memory : 1;
				std::uint32_t m_force_wake_charge : 1;
				std::uint32_t m_cross_session_create : 1;
				std::uint32_t m_needs_handle_rundown : 1;
				std::uint32_t m_ref_trace_enabled : 1;
				std::uint32_t m_force_ws_watch : 1;
				std::uint32_t m_create_reported : 1;
				std::uint32_t m_default_io_priority : 3;
				std::uint32_t m_spare_bits : 17;
			};
		};

		union {
			std::uint32_t m_flags;                                          // +0x464
			struct {
				std::uint32_t m_create_time_reported : 1;
				std::uint32_t m_image_not_loaded : 1;
				std::uint32_t m_process_exiting : 1;
				std::uint32_t m_process_delete : 1;
				std::uint32_t m_wow64_split_pages : 1;
				std::uint32_t m_vm_deleted : 1;
				std::uint32_t m_outswap_enabled : 1;
				std::uint32_t m_outswapped : 1;
				std::uint32_t m_fork_failed : 1;
				std::uint32_t m_has_address_space : 1;
				std::uint32_t m_address_space_initialized : 2;
				std::uint32_t m_set_timer_resolution : 1;
				std::uint32_t m_break_on_termination : 1;
				std::uint32_t m_dependent_on_session : 1;
				std::uint32_t m_auto_alignment : 1;
				std::uint32_t m_prefer_32bit : 1;
				std::uint32_t m_wow64_valid : 1;
				std::uint32_t m_cross_session_create : 1;
				std::uint32_t m_spare_flags0 : 13;
			};
		};

		std::int64_t m_create_time;                                         // +0x468
		std::uint64_t m_process_quota_usage[2];                            // +0x470
		std::uint64_t m_process_quota_peak[2];                             // +0x480
		std::uint64_t m_peak_virtual_size;                                 // +0x490
		std::uint64_t m_virtual_size;                                      // +0x498
		LIST_ENTRY m_session_process_links;                              // +0x4A0
		union {
			void* m_exception_port;                                         // +0x4B0
			std::uint64_t m_exception_port_value;                          // +0x4B0
		};
		ex_fast_ref_t m_token;                                             // +0x4B8
		std::uint64_t m_working_set_page_count;                           // +0x4C0
		EX_PUSH_LOCK m_address_creation_lock;                            // +0x4C8
		EX_PUSH_LOCK m_page_table_commit_lock;                          // +0x4D0
		void* m_rotate_in_progress;                                        // +0x4D8
		void* m_fork_in_progress;                                          // +0x4E0
		std::uint64_t m_hardware_counters;                                // +0x4E8
		void* m_spare_ptr0;                                                // +0x4F0
		std::uint64_t m_spare_ulong0;                                     // +0x4F8
		std::uint64_t m_spare_ulong1;                                     // +0x500
		std::uint64_t m_spare_ulong2;                                     // +0x508
		std::uint64_t m_spare_ulong3;                                     // +0x510
		void* m_section_object;                                            // +0x518
		void* m_section_base_address;                                      // +0x520
		std::uint32_t m_cookie;                                           // +0x528
		std::uint32_t m_padding1;                                         // +0x52C
		void* m_working_set_watch;                                         // +0x530
		void* m_win32_window_station;                                      // +0x538
		void* m_inherited_from_unique_process_id;                          // +0x540
		void* m_peb;                                                       // +0x548
		void* m_session;                                                   // +0x550
		void* m_spare1;                                                    // +0x558
		void* m_quota_block;                                               // +0x560
		void* m_object_table;                                              // +0x568
		void* m_debug_port;                                                // +0x570
		void* m_wow64_process;                                             // +0x578
		ex_fast_ref_t m_device_map;                                        // +0x580
		void* m_etw_data_source;                                           // +0x588
		std::uint64_t m_page_directory_pte;                               // +0x590
		void* m_image_file_pointer;                                        // +0x598
		char m_image_file_name[15];                                        // +0x5A0
		std::uint8_t m_priority_class;                                     // +0x5AF
		void* m_security_port;                                             // +0x5B0
		se_audit_process_creation_info_t m_se_audit_process_creation_info; // +0x5B8
		LIST_ENTRY m_job_links;                                         // +0x5C0
		void* m_spare2;                                                    // +0x5D0
		LIST_ENTRY m_thread_list_head;                                  // +0x5D8
		std::uint32_t m_active_threads;                                   // +0x5E8
		std::uint32_t m_image_path_hash;                                  // +0x5EC
		std::uint32_t m_default_harderror_processing;                     // +0x5F0
		std::int32_t m_last_thread_exit_status;                          // +0x5F4
		void* m_pde_table;                                                // +0x5F8
	};

	struct physical_memory_range_t {
		ULARGE_INTEGER m_base_page;
		ULARGE_INTEGER m_page_count;
	};

	struct dos_header_t {
		std::int16_t m_magic;
		std::int16_t m_cblp;
		std::int16_t m_cp;
		std::int16_t m_crlc;
		std::int16_t m_cparhdr;
		std::int16_t m_minalloc;
		std::int16_t m_maxalloc;
		std::int16_t m_ss;
		std::int16_t m_sp;
		std::int16_t m_csum;
		std::int16_t m_ip;
		std::int16_t m_cs;
		std::int16_t m_lfarlc;
		std::int16_t m_ovno;
		std::int16_t m_res0[0x4];
		std::int16_t m_oemid;
		std::int16_t m_oeminfo;
		std::int16_t m_res1[0xa];
		std::int32_t m_lfanew;

		[[ nodiscard ]]
		constexpr bool is_valid() {
			return m_magic == pe_magic_t::dos_header;
		}
	};

	struct export_directory_t {
		std::int32_t m_characteristics;
		std::int32_t m_time_date_stamp;
		std::int16_t m_major_version;
		std::int16_t m_minor_version;
		std::int32_t m_name;
		std::int32_t m_base;
		std::int32_t m_number_of_functions;
		std::int32_t m_number_of_names;
		std::int32_t m_address_of_functions;
		std::int32_t m_address_of_names;
		std::int32_t m_address_of_names_ordinals;
	};

	struct data_directory_t {
		std::int32_t m_virtual_address;
		std::int32_t m_size;

		template< class type_t, typename addr_t >
		[[ nodiscard ]]
		type_t as_rva(
			addr_t rva
		) {
			return reinterpret_cast<type_t>(rva + m_virtual_address);
		}
	};

	struct nt_headers_t {
		std::int32_t m_signature;
		std::int16_t m_machine;
		std::int16_t m_number_of_sections;
		std::int32_t m_time_date_stamp;
		std::int32_t m_pointer_to_symbol_table;
		std::int32_t m_number_of_symbols;
		std::int16_t m_size_of_optional_header;
		std::int16_t m_characteristics;

		std::int16_t m_magic;
		std::int8_t m_major_linker_version;
		std::int8_t m_minor_linker_version;
		std::int32_t m_size_of_code;
		std::int32_t m_size_of_initialized_data;
		std::int32_t m_size_of_uninitialized_data;
		std::int32_t m_address_of_entry_point;
		std::int32_t m_base_of_code;
		std::uint64_t m_image_base;
		std::int32_t m_section_alignment;
		std::int32_t m_file_alignment;
		std::int16_t m_major_operating_system_version;
		std::int16_t m_minor_operating_system_version;
		std::int16_t m_major_image_version;
		std::int16_t m_minor_image_version;
		std::int16_t m_major_subsystem_version;
		std::int16_t m_minor_subsystem_version;
		std::int32_t m_win32_version_value;
		std::int32_t m_size_of_image;
		std::int32_t m_size_of_headers;
		std::int32_t m_check_sum;
		std::int16_t m_subsystem;
		std::int16_t m_dll_characteristics;
		std::uint64_t m_size_of_stack_reserve;
		std::uint64_t m_size_of_stack_commit;
		std::uint64_t m_size_of_heap_reserve;
		std::uint64_t m_size_of_heap_commit;
		std::int32_t m_loader_flags;
		std::int32_t m_number_of_rva_and_sizes;

		data_directory_t m_export_table;
		data_directory_t m_import_table;
		data_directory_t m_resource_table;
		data_directory_t m_exception_table;
		data_directory_t m_certificate_table;
		data_directory_t m_base_relocation_table;
		data_directory_t m_debug;
		data_directory_t m_architecture;
		data_directory_t m_global_ptr;
		data_directory_t m_tls_table;
		data_directory_t m_load_config_table;
		data_directory_t m_bound_import;
		data_directory_t m_iat;
		data_directory_t m_delay_import_descriptor;
		data_directory_t m_clr_runtime_header;
		data_directory_t m_reserved;

		[[ nodiscard ]]
		constexpr bool is_valid() {
			return m_signature == pe_magic_t::nt_headers
				&& m_magic == pe_magic_t::opt_header;
		}
	};

	typedef struct _rtl_process_module_information
	{
		HANDLE section;
		PVOID mapped_base;
		PVOID image_base;
		ULONG image_size;
		ULONG flags;
		USHORT load_order_index;
		USHORT init_order_index;
		USHORT load_count;
		USHORT offset_to_name;
		UCHAR  path_name[256];
	} rtl_process_module_information, * prtl_process_module_information;

	struct pt_entries_t {
		pml4e m_pml4e;
		pdpte m_pdpte;
		pde m_pde;
		pte m_pte;
	};

	typedef struct _SYSTEM_MODULE_ENTRY
	{
#ifdef _WIN64
		ULONGLONG Unknown1;
		ULONGLONG Unknown2;
#else
		ULONG Unknown1;
		ULONG Unknown2;
#endif
		PVOID BaseAddress;
		ULONG Size;
		ULONG Flags;
		ULONG EntryIndex;
		USHORT NameLength;  // Length of module name not including the path, this field contains valid value only for NTOSKRNL module
		USHORT PathLength;  // Length of 'directory path' part of modulename
		CHAR Name[MAXIMUM_FILENAME_LENGTH];
	} SYSTEM_MODULE_ENTRY;

#pragma pack(push, 1)
	typedef struct _IDSECTOR
	{
		USHORT wGenConfig;
		USHORT wNumCyls;
		USHORT wReserved;
		USHORT wNumHeads;
		USHORT wBytesPerTrack;
		USHORT wBytesPerSector;
		USHORT wSectorsPerTrack;
		USHORT wVendorUnique[3];
		CHAR   sSerialNumber[20];
		USHORT wBufferType;
		USHORT wBufferSize;
		USHORT wECCSize;
		CHAR   sFirmwareRev[8];
		CHAR   sModelNumber[40];
		USHORT wMoreVendorUnique;
		USHORT wDoubleWordIO;
		USHORT wCapabilities;
		USHORT wReserved1;
		USHORT wPIOTiming;
		USHORT wDMATiming;
		USHORT wBS;
		USHORT wNumCurrentCyls;
		USHORT wNumCurrentHeads;
		USHORT wNumCurrentSectorsPerTrack;
		ULONG  ulCurrentSectorCapacity;
		USHORT wMultSectorStuff;
		ULONG  ulTotalAddressableSectors;
		USHORT wSingleWordDMA;
		USHORT wMultiWordDMA;
		UCHAR  bReserved[128];  // Changed BYTE to UCHAR for consistency
	} IDSECTOR, * PIDSECTOR;
#pragma pack(pop)

	// =============================================
	// Intel NVMe Payload
	// =============================================

#pragma pack(push, 1)
	typedef struct _INTEL_NVME_PAYLOAD
	{
		UCHAR  Version;              // 0x001C
		UCHAR  PathId;               // 0x001D
		UCHAR  TargetID;             // 0x001E
		UCHAR  Lun;                  // 0x001F
		NVME_CMD Cmd;                // 0x0020 ~ 0x005F
		ULONG  CplEntry[4];          // 0x0060 ~ 0x006F
		ULONG  QueueId;              // 0x0070 ~ 0x0073
		ULONG  ParamBufLen;          // 0x0074
		ULONG  ReturnBufferLen;      // 0x0078
		UCHAR  Reserved[0x28];       // 0x007C ~ 0xA3
	} INTEL_NVME_PAYLOAD, * PINTEL_NVME_PAYLOAD;
#pragma pack(pop)

	// =============================================
	// Intel NVMe Pass-Through (With Buffer)
	// =============================================

#pragma pack(push, 1)
	typedef struct _INTEL_NVME_PASS_THROUGH
	{
		INTEL_NVME_PAYLOAD Payload;
		UCHAR DataBuffer[4096];      // Add buffer here
	} INTEL_NVME_PASS_THROUGH, * PINTEL_NVME_PASS_THROUGH;
#pragma pack(pop)

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG Count;
#ifdef _WIN64
		ULONG Unknown1;
#endif
		SYSTEM_MODULE_ENTRY Module[1];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;;

	typedef struct _IOC_REQUEST {
		PVOID Buffer;
		ULONG BufferLength;
		PVOID OldContext;
		PIO_COMPLETION_ROUTINE OldRoutine;
	} IOC_REQUEST, * PIOC_REQUEST;

	typedef struct _rtl_process_modules
	{
		ULONG number_of_modules;
		rtl_process_module_information module_list[1];
	} rtl_process_modules, * prtl_process_modules;

	typedef enum DRS
	{
		STATUS_LEAVE_ALONE,
		STATUS_NOT_HANDLED,
	};

}
namespace pdb_definitions
{
	constexpr ULONG_PTR PmFilterDeviceControlRva = 0x38D0;
	constexpr ULONG_PTR RaInitializeDriverRva = 0x6C10;
	constexpr ULONG_PTR MountMgrDeviceControlRva = 0x9010;
	constexpr ULONG_PTR IoctlToNVMeRva = 0x14870;
	constexpr ULONG_PTR EvtWmiMonitorIDQueryBlock = 0xF070;
	constexpr ULONG_PTR NsippDispatch = 0x1440;
	constexpr ULONG_PTR NtAllocateUuids = 0x681EE0;
	constexpr ULONG_PTR NbtDispatchDevCtrl = 0x15CB0;
	constexpr ULONG_PTR NbtQueryAdapterStatus = 0x11D20;
	constexpr ULONG_PTR ndisDeviceControlHandler = 0x10F30;
	constexpr ULONG_PTR TdxTdiDispatchDeviceControl = 0x145A0;
}

namespace e_definitions {



	inline std::uint8_t* i_ntos_base;
	inline PEPROCESS* i_pe_process;
	inline std::uint64_t m_target_cr3{ };
	inline std::uint64_t i_system_cr3{ };

	inline e_structures::eprocess_t* i_system_process;
	inline e_structures::page_mapping_t m_page_mappings[64] = {};
	inline bool m_is_initialized = false;

	constexpr auto page_4kb_size = 0x1000ull;
	constexpr auto page_2mb_size = 0x200000ull;
	constexpr auto page_1gb_size = 0x40000000ull;

	constexpr auto page_shift = 12ull;
	constexpr auto page_2mb_shift = 21ull;
	constexpr auto page_1gb_shift = 30ull;

	constexpr auto page_4kb_mask = 0xFFFull;
	constexpr auto page_2mb_mask = 0x1FFFFFull;
	constexpr auto page_1gb_mask = 0x3FFFFFFFull;
}

namespace shellcode_definitions {
	constexpr std::uint8_t detour_shellcode[] = {
		// inline relative
		0xE9, 0x00, 0x00, 0x00, 0x00 // jmp <relative address>
	};

	constexpr size_t detour_size = sizeof(detour_shellcode);
}

#define SCSI_VPD_DEVICE_IDENTIFICATION 0x83

#define F_MODRM         0x00000001
#define F_SIB           0x00000002
#define F_IMM8          0x00000004
#define F_IMM16         0x00000008
#define F_IMM32         0x00000010
#define F_IMM64         0x00000020
#define F_DISP8         0x00000040
#define F_DISP16        0x00000080
#define F_DISP32        0x00000100
#define F_RELATIVE      0x00000200
#define F_ERROR         0x00001000
#define F_ERROR_OPCODE  0x00002000
#define F_ERROR_LENGTH  0x00004000
#define F_ERROR_LOCK    0x00008000
#define F_ERROR_OPERAND 0x00010000
#define F_PREFIX_REPNZ  0x01000000
#define F_PREFIX_REPX   0x02000000
#define F_PREFIX_REP    0x03000000
#define F_PREFIX_66     0x04000000
#define F_PREFIX_67     0x08000000
#define F_PREFIX_LOCK   0x10000000
#define F_PREFIX_SEG    0x20000000
#define F_PREFIX_REX    0x40000000
#define F_PREFIX_ANY    0x7f000000

#define PREFIX_SEGMENT_CS   0x2e
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3e
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xf0
#define PREFIX_REPNZ        0xf2
#define PREFIX_REPX         0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

#define C_NONE    0x00
#define C_MODRM   0x01
#define C_IMM8    0x02
#define C_IMM16   0x04
#define C_IMM_P66 0x10
#define C_REL8    0x20
#define C_REL32   0x40
#define C_GROUP   0x80
#define C_ERROR   0xff

#define PRE_ANY  0x00
#define PRE_NONE 0x01
#define PRE_F2   0x02
#define PRE_F3   0x04
#define PRE_66   0x08
#define PRE_67   0x10
#define PRE_LOCK 0x20
#define PRE_SEG  0x40
#define PRE_ALL  0xff

#define DELTA_OPCODES      0x4a
#define DELTA_FPU_REG      0xfd
#define DELTA_FPU_MODRM    0x104
#define DELTA_PREFIXES     0x13c
#define DELTA_OP_LOCK_OK   0x1ae
#define DELTA_OP2_LOCK_OK  0x1c6
#define DELTA_OP_ONLY_MEM  0x1d8
#define DELTA_OP2_ONLY_MEM 0x1e7

unsigned char hde64_table[] = {
  0xa5,0xaa,0xa5,0xb8,0xa5,0xaa,0xa5,0xaa,0xa5,0xb8,0xa5,0xb8,0xa5,0xb8,0xa5,
  0xb8,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xac,0xc0,0xcc,0xc0,0xa1,0xa1,
  0xa1,0xa1,0xb1,0xa5,0xa5,0xa6,0xc0,0xc0,0xd7,0xda,0xe0,0xc0,0xe4,0xc0,0xea,
  0xea,0xe0,0xe0,0x98,0xc8,0xee,0xf1,0xa5,0xd3,0xa5,0xa5,0xa1,0xea,0x9e,0xc0,
  0xc0,0xc2,0xc0,0xe6,0x03,0x7f,0x11,0x7f,0x01,0x7f,0x01,0x3f,0x01,0x01,0xab,
  0x8b,0x90,0x64,0x5b,0x5b,0x5b,0x5b,0x5b,0x92,0x5b,0x5b,0x76,0x90,0x92,0x92,
  0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x6a,0x73,0x90,
  0x5b,0x52,0x52,0x52,0x52,0x5b,0x5b,0x5b,0x5b,0x77,0x7c,0x77,0x85,0x5b,0x5b,
  0x70,0x5b,0x7a,0xaf,0x76,0x76,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,
  0x5b,0x5b,0x86,0x01,0x03,0x01,0x04,0x03,0xd5,0x03,0xd5,0x03,0xcc,0x01,0xbc,
  0x03,0xf0,0x03,0x03,0x04,0x00,0x50,0x50,0x50,0x50,0xff,0x20,0x20,0x20,0x20,
  0x01,0x01,0x01,0x01,0xc4,0x02,0x10,0xff,0xff,0xff,0x01,0x00,0x03,0x11,0xff,
  0x03,0xc4,0xc6,0xc8,0x02,0x10,0x00,0xff,0xcc,0x01,0x01,0x01,0x00,0x00,0x00,
  0x00,0x01,0x01,0x03,0x01,0xff,0xff,0xc0,0xc2,0x10,0x11,0x02,0x03,0x01,0x01,
  0x01,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0x00,0x00,0xff,0xff,0xff,0xff,0x10,
  0x10,0x10,0x10,0x02,0x10,0x00,0x00,0xc6,0xc8,0x02,0x02,0x02,0x02,0x06,0x00,
  0x04,0x00,0x02,0xff,0x00,0xc0,0xc2,0x01,0x01,0x03,0x03,0x03,0xca,0x40,0x00,
  0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,0x00,0x00,0x00,
  0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0xff,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
  0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7f,0x00,0x00,
  0xff,0x40,0x40,0x40,0x40,0x41,0x49,0x40,0x40,0x40,0x40,0x4c,0x42,0x40,0x40,
  0x40,0x40,0x40,0x40,0x40,0x40,0x4f,0x44,0x53,0x40,0x40,0x40,0x44,0x57,0x43,
  0x5c,0x40,0x60,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
  0x40,0x40,0x64,0x66,0x6e,0x6b,0x40,0x40,0x6a,0x46,0x40,0x40,0x44,0x46,0x40,
  0x40,0x5b,0x44,0x40,0x40,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x06,0x01,0x06,
  0x06,0x02,0x06,0x06,0x00,0x06,0x00,0x0a,0x0a,0x00,0x00,0x00,0x02,0x07,0x07,
  0x06,0x02,0x0d,0x06,0x06,0x06,0x0e,0x05,0x05,0x02,0x02,0x00,0x00,0x04,0x04,
  0x04,0x04,0x05,0x06,0x06,0x06,0x00,0x00,0x00,0x0e,0x00,0x00,0x08,0x00,0x10,
  0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,0x86,0x00,
  0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,0xf8,0xbb,
  0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,0xc4,0xff,
  0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0x0e,0x12,0x08,0x00,0x13,0x09,
  0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0x07,0xb2,0xff,
  0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,0xe7,0x08,
  0x00,0xf0,0x02,0x00
};


namespace external_functions {
	extern "C" NTSYSAPI NTSTATUS ZwQuerySystemInformation(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

#pragma warning(push)
#pragma warning(disable:4706)

	unsigned int hde64_disasm(const void* code, e_structures::hde64s* hs)
	{
		uint8_t x, c = 0, * p = (uint8_t*)code, cflags, opcode, pref = 0;
		uint8_t* ht = hde64_table, m_mod, m_reg, m_rm, disp_size = 0;
		uint8_t op64 = 0;

		__stosb((unsigned char*)hs, 0, sizeof(e_structures::hde64s));

		for (x = 16; x; x--)
			switch (c = *p++) {
			case 0xf3:
				hs->p_rep = c;
				pref |= PRE_F3;
				break;
			case 0xf2:
				hs->p_rep = c;
				pref |= PRE_F2;
				break;
			case 0xf0:
				hs->p_lock = c;
				pref |= PRE_LOCK;
				break;
			case 0x26: case 0x2e: case 0x36:
			case 0x3e: case 0x64: case 0x65:
				hs->p_seg = c;
				pref |= PRE_SEG;
				break;
			case 0x66:
				hs->p_66 = c;
				pref |= PRE_66;
				break;
			case 0x67:
				hs->p_67 = c;
				pref |= PRE_67;
				break;
			default:
				goto pref_done;
			}
	pref_done:

		hs->flags = (uint32_t)pref << 23;

		if (!pref)
			pref |= PRE_NONE;

		if ((c & 0xf0) == 0x40) {
			hs->flags |= F_PREFIX_REX;
			if ((hs->rex_w = (c & 0xf) >> 3) && (*p & 0xf8) == 0xb8)
				op64++;
			hs->rex_r = (c & 7) >> 2;
			hs->rex_x = (c & 3) >> 1;
			hs->rex_b = c & 1;
			if (((c = *p++) & 0xf0) == 0x40) {
				opcode = c;
				goto error_opcode;
			}
		}

		if ((hs->opcode = c) == 0x0f) {
			hs->opcode2 = c = *p++;
			ht += DELTA_OPCODES;
		}
		else if (c >= 0xa0 && c <= 0xa3) {
			op64++;
			if (pref & PRE_67)
				pref |= PRE_66;
			else
				pref &= ~PRE_66;
		}

		opcode = c;
		cflags = ht[ht[opcode / 4] + (opcode % 4)];

		if (cflags == C_ERROR) {
		error_opcode:
			hs->flags |= F_ERROR | F_ERROR_OPCODE;
			cflags = 0;
			if ((opcode & -3) == 0x24)
				cflags++;
		}

		x = 0;
		if (cflags & C_GROUP) {
			uint16_t t;
			t = *(uint16_t*)(ht + (cflags & 0x7f));
			cflags = (uint8_t)t;
			x = (uint8_t)(t >> 8);
		}

		if (hs->opcode2) {
			ht = hde64_table + DELTA_PREFIXES;
			if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
				hs->flags |= F_ERROR | F_ERROR_OPCODE;
		}

		if (cflags & C_MODRM) {
			hs->flags |= F_MODRM;
			hs->modrm = c = *p++;
			hs->modrm_mod = m_mod = c >> 6;
			hs->modrm_rm = m_rm = c & 7;
			hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

			if (x && ((x << m_reg) & 0x80))
				hs->flags |= F_ERROR | F_ERROR_OPCODE;

			if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
				uint8_t t = opcode - 0xd9;
				if (m_mod == 3) {
					ht = hde64_table + DELTA_FPU_MODRM + t * 8;
					t = ht[m_reg] << m_rm;
				}
				else {
					ht = hde64_table + DELTA_FPU_REG;
					t = ht[t] << m_reg;
				}
				if (t & 0x80)
					hs->flags |= F_ERROR | F_ERROR_OPCODE;
			}

			if (pref & PRE_LOCK) {
				if (m_mod == 3) {
					hs->flags |= F_ERROR | F_ERROR_LOCK;
				}
				else {
					uint8_t* table_end, op = opcode;
					if (hs->opcode2) {
						ht = hde64_table + DELTA_OP2_LOCK_OK;
						table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
					}
					else {
						ht = hde64_table + DELTA_OP_LOCK_OK;
						table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
						op &= -2;
					}
					for (; ht != table_end; ht++)
						if (*ht++ == op) {
							if (!((*ht << m_reg) & 0x80))
								goto no_lock_error;
							else
								break;
						}
					hs->flags |= F_ERROR | F_ERROR_LOCK;
				no_lock_error:
					;
				}
			}

			if (hs->opcode2) {
				switch (opcode) {
				case 0x20: case 0x22:
					m_mod = 3;
					if (m_reg > 4 || m_reg == 1)
						goto error_operand;
					else
						goto no_error_operand;
				case 0x21: case 0x23:
					m_mod = 3;
					if (m_reg == 4 || m_reg == 5)
						goto error_operand;
					else
						goto no_error_operand;
				}
			}
			else {
				switch (opcode) {
				case 0x8c:
					if (m_reg > 5)
						goto error_operand;
					else
						goto no_error_operand;
				case 0x8e:
					if (m_reg == 1 || m_reg > 5)
						goto error_operand;
					else
						goto no_error_operand;
				}
			}

			if (m_mod == 3) {
				uint8_t* table_end;
				if (hs->opcode2) {
					ht = hde64_table + DELTA_OP2_ONLY_MEM;
					table_end = ht + sizeof(hde64_table) - DELTA_OP2_ONLY_MEM;
				}
				else {
					ht = hde64_table + DELTA_OP_ONLY_MEM;
					table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
				}
				for (; ht != table_end; ht += 2)
					if (*ht++ == opcode) {
						if (*ht++ & pref && !((*ht << m_reg) & 0x80))
							goto error_operand;
						else
							break;
					}
				goto no_error_operand;
			}
			else if (hs->opcode2) {
				switch (opcode) {
				case 0x50: case 0xd7: case 0xf7:
					if (pref & (PRE_NONE | PRE_66))
						goto error_operand;
					break;
				case 0xd6:
					if (pref & (PRE_F2 | PRE_F3))
						goto error_operand;
					break;
				case 0xc5:
					goto error_operand;
				}
				goto no_error_operand;
			}
			else
				goto no_error_operand;

		error_operand:
			hs->flags |= F_ERROR | F_ERROR_OPERAND;
		no_error_operand:

			c = *p++;
			if (m_reg <= 1) {
				if (opcode == 0xf6)
					cflags |= C_IMM8;
				else if (opcode == 0xf7)
					cflags |= C_IMM_P66;
			}

			switch (m_mod) {
			case 0:
				if (pref & PRE_67) {
					if (m_rm == 6)
						disp_size = 2;
				}
				else
					if (m_rm == 5)
						disp_size = 4;
				break;
			case 1:
				disp_size = 1;
				break;
			case 2:
				disp_size = 2;
				if (!(pref & PRE_67))
					disp_size <<= 1;
			}

			if (m_mod != 3 && m_rm == 4) {
				hs->flags |= F_SIB;
				p++;
				hs->sib = c;
				hs->sib_scale = c >> 6;
				hs->sib_index = (c & 0x3f) >> 3;
				if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
					disp_size = 4;
			}

			p--;
			switch (disp_size) {
			case 1:
				hs->flags |= F_DISP8;
				hs->disp.disp8 = *p;
				break;
			case 2:
				hs->flags |= F_DISP16;
				hs->disp.disp16 = *(uint16_t*)p;
				break;
			case 4:
				hs->flags |= F_DISP32;
				hs->disp.disp32 = *(uint32_t*)p;
			}
			p += disp_size;
		}
		else if (pref & PRE_LOCK)
			hs->flags |= F_ERROR | F_ERROR_LOCK;

		if (cflags & C_IMM_P66) {
			if (cflags & C_REL32) {
				if (pref & PRE_66) {
					hs->flags |= F_IMM16 | F_RELATIVE;
					hs->imm.imm16 = *(uint16_t*)p;
					p += 2;
					goto disasm_done;
				}
				goto rel32_ok;
			}
			if (op64) {
				hs->flags |= F_IMM64;
				hs->imm.imm64 = *(uint64_t*)p;
				p += 8;
			}
			else if (!(pref & PRE_66)) {
				hs->flags |= F_IMM32;
				hs->imm.imm32 = *(uint32_t*)p;
				p += 4;
			}
			else
				goto imm16_ok;
		}


		if (cflags & C_IMM16) {
		imm16_ok:
			hs->flags |= F_IMM16;
			hs->imm.imm16 = *(uint16_t*)p;
			p += 2;
		}
		if (cflags & C_IMM8) {
			hs->flags |= F_IMM8;
			hs->imm.imm8 = *p++;
		}

		if (cflags & C_REL32) {
		rel32_ok:
			hs->flags |= F_IMM32 | F_RELATIVE;
			hs->imm.imm32 = *(uint32_t*)p;
			p += 4;
		}
		else if (cflags & C_REL8) {
			hs->flags |= F_IMM8 | F_RELATIVE;
			hs->imm.imm8 = *p++;
		}

	disasm_done:

		if ((hs->len = (uint8_t)(p - (uint8_t*)code)) > 15) {
			hs->flags |= F_ERROR | F_ERROR_LENGTH;
			hs->len = 15;
		}

		return (unsigned int)hs->len;
	}

#pragma warning(pop) // 4706


	ULONG
		km_strtoul(
			const char* str,
			char** end,
			ULONG base
		)
	{
		const char* s = str;
		ULONG result = 0;
		ULONG cutoff;
		ULONG cutlim;
		BOOLEAN negative = FALSE;

		if (!s)
		{
			if (end) *end = nullptr;
			return 0;
		}

		// Skip leading whitespace
		while (*s == ' ' || *s == '\t' || *s == '\n' ||
			*s == '\r' || *s == '\f' || *s == '\v')
		{
			++s;
		}

		// Sign
		if (*s == '+' || *s == '-')
		{
			negative = (*s == '-');
			++s;
		}

		// Base autodetection
		if (base == 0)
		{
			if (*s == '0')
			{
				if ((s[1] == 'x' || s[1] == 'X'))
				{
					base = 16;
					s += 2;
				}
				else
				{
					base = 8;
					++s;
				}
			}
			else
			{
				base = 10;
			}
		}
		else if (base == 16)
		{
			if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
			{
				s += 2;
			}
		}

		if (base < 2 || base > 36)
		{
			if (end) *end = const_cast<char*>(str);
			return 0;
		}

		cutoff = MAXULONG / base;
		cutlim = MAXULONG % base;

		BOOLEAN any = FALSE;

		for (;; ++s)
		{
			ULONG digit;

			if (*s >= '0' && *s <= '9')
				digit = *s - '0';
			else if (*s >= 'A' && *s <= 'Z')
				digit = *s - 'A' + 10;
			else if (*s >= 'a' && *s <= 'z')
				digit = *s - 'a' + 10;
			else
				break;

			if (digit >= base)
				break;

			if (result > cutoff || (result == cutoff && digit > cutlim))
			{
				result = MAXULONG;
				any = TRUE;
				break;
			}

			any = TRUE;
			result = result * base + digit;
		}

		if (end)
			*end = const_cast<char*>(any ? s : str);

		if (negative)
			return (ULONG)(-(LONG)result);

		return result;
	}
}