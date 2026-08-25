#pragma once
#include <definitions/definitions.hxx>
#include <ntimage.h>
#include <minwindef.h>

namespace export_handler {
    inline bool get_ntos_base()
    {
        ULONG bytes = 0;
        NTSTATUS status = external_functions::ZwQuerySystemInformation(11, nullptr, 0, &bytes);

        DbgPrint("[Impala] Query size result: 0x%X, bytes needed: %lu\n", status, bytes);

        if (!bytes)
        {
            DbgPrint("[Impala] No bytes returned\n");
            return false;
        }

        auto modules = (e_structures::prtl_process_modules)ExAllocatePoolWithTag(NonPagedPool,bytes,'bKRN');

        if (!modules)
        {
            DbgPrint("[Impala] Failed to allocate %lu bytes\n", bytes);
            return false;
        }

        DbgPrint("[Impala] Allocated buffer at: 0x%p\n", modules);

        status = external_functions::ZwQuerySystemInformation(11, modules, bytes, &bytes);

        DbgPrint("[Impala] Query modules result: 0x%X\n", status);

        if (!NT_SUCCESS(status))
        {
            DbgPrint("[Impala] ZwQuerySystemInformation failed: 0x%X\n", status);
            ExFreePoolWithTag(modules, 'bKRN');
            return false;
        }

        DbgPrint("[Impala] Number of modules: %lu\n", modules->number_of_modules);

        if (modules->number_of_modules == 0)
        {
            DbgPrint("[Impala] No modules returned!\n");
            ExFreePoolWithTag(modules, 'bKRN');
            return false;
        }

        DbgPrint("[Impala] First module info:\n");
        DbgPrint("          section: 0x%p\n", modules->module_list[0].section);
        DbgPrint("          mapped_base: 0x%p\n", modules->module_list[0].mapped_base);
        DbgPrint("          image_base: 0x%p\n", modules->module_list[0].image_base);
        DbgPrint("          image_size: 0x%X\n", modules->module_list[0].image_size);
        DbgPrint("          path_name: %s\n", modules->module_list[0].path_name);

        UINT64 ntoskrnlBase = (UINT64)modules->module_list[0].image_base;

        DbgPrint("[Impala] ntoskrnlBase = 0x%llX\n", ntoskrnlBase);

        ExFreePoolWithTag(modules, 'bKRN');

        if (ntoskrnlBase < 0xFFFF800000000000ULL || ntoskrnlBase > 0xFFFFFFFFFFFFFFFFULL)
        {
            DbgPrint("[Impala] Invalid kernel address: 0x%llX\n", ntoskrnlBase);
            return false;
        }

        e_definitions::i_ntos_base = (std::uint8_t*)ntoskrnlBase;

        DbgPrint("[Impala] i_ntos_base set to: 0x%p\n", e_definitions::i_ntos_base);

        return true;
    }

    inline ULONG64 get_export(const char* export_name) {
        if (MmIsAddressValid(e_definitions::i_ntos_base) == FALSE) {
            DbgPrint(("[Impala] i_ntos_base is not valid!\n"));
            return 0;
		}
        auto dos_header{ reinterpret_cast<e_structures::dos_header_t*> (e_definitions::i_ntos_base) };
        auto nt_headers{ reinterpret_cast<e_structures::nt_headers_t*> (e_definitions::i_ntos_base + dos_header->m_lfanew) };
        if (!dos_header->is_valid()
            || !nt_headers->is_valid())
            return {};

        auto exp_dir{ nt_headers->m_export_table.as_rva< e_structures::export_directory_t* >(e_definitions::i_ntos_base) };
        if (!exp_dir->m_address_of_functions
            || !exp_dir->m_address_of_names
            || !exp_dir->m_address_of_names_ordinals)
            return {};

        auto name{ reinterpret_cast<std::int32_t*> (e_definitions::i_ntos_base + exp_dir->m_address_of_names) };
        auto func{ reinterpret_cast<std::int32_t*> (e_definitions::i_ntos_base + exp_dir->m_address_of_functions) };
        auto ords{ reinterpret_cast<std::int16_t*> (e_definitions::i_ntos_base + exp_dir->m_address_of_names_ordinals) };

        for (std::int32_t i{}; i < exp_dir->m_number_of_names; i++) {
            auto cur_name{ e_definitions::i_ntos_base + name[i] };
            auto cur_func{ e_definitions::i_ntos_base + func[ords[i]] };
            if (!cur_name
                || !cur_func)
                continue;

            if (strcmp(export_name, reinterpret_cast<char*>(cur_name)) == 0)
                return (std::uint64_t)cur_func;
        }
        return 0;
    }

    bool get_section(const char* section_name, std::uint64_t* exec_base, std::uint64_t* exec_size) {
        auto dos_header{ reinterpret_cast<e_structures::dos_header_t*> (e_definitions::i_ntos_base) };
        auto nt_headers{ reinterpret_cast<e_structures::nt_headers_t*> (e_definitions::i_ntos_base + dos_header->m_lfanew) };

        if (!dos_header->is_valid() || !nt_headers->is_valid())
            return false;

        auto section_header = reinterpret_cast<e_structures::section_header_t*>(reinterpret_cast<std::uintptr_t>(nt_headers) + nt_headers->m_size_of_optional_header + 0x18);
        for (int i = 0; i < nt_headers->m_number_of_sections; i++) {
            auto current_section_base = reinterpret_cast<std::uint64_t>(dos_header) + section_header[i].m_virtual_address;
            if (!strcmp(section_header[i].m_name, section_name)) {
                *exec_base = current_section_base;
                *exec_size = section_header[i].m_size_of_raw_data;
                break;
            }
        }

        return *exec_base && *exec_size;
    }
}

namespace byte_handler {
    std::uintptr_t private_sig_scan(std::uintptr_t base, size_t size, const std::uint8_t* signature, const char* mask) {
        const auto sig_length = strlen(mask);

        if (sig_length == 0 || size < sig_length)
            return 0;

        for (size_t i = 0; i <= size - sig_length; ++i) {
            bool found = true;

            for (size_t j = 0; j < sig_length; ++j) {
                if (mask[j] == 'x' && *reinterpret_cast<const std::uint8_t*>(base + i + j) != signature[j]) {
                    found = false;
                    break;
                }
            }

            if (found)
                return base + i;
        }

        return 0;
    }

    bool next_exec_section(std::uint64_t* exec_base, std::uint64_t* exec_size) {
        auto dos_header{ reinterpret_cast<e_structures::dos_header_t*> (e_definitions::i_ntos_base) };
        auto nt_headers{ reinterpret_cast<e_structures::nt_headers_t*> (e_definitions::i_ntos_base + dos_header->m_lfanew) };
        if (!dos_header->is_valid() || !nt_headers->is_valid())
            return false;

        auto section_header = reinterpret_cast<e_structures::section_header_t*>(reinterpret_cast<std::uintptr_t>(nt_headers) + nt_headers->m_size_of_optional_header + 0x18);
        for (int i = 0; i < nt_headers->m_number_of_sections; i++) {
            auto current_section_base = reinterpret_cast<std::uint64_t>(dos_header) + section_header[i].m_virtual_address;
            if (section_header[i].m_characteristics & 0x20000000) {
                *exec_base = current_section_base;
                *exec_size = section_header[i].m_size_of_raw_data;
                break;
            }
        }

        return *exec_base && *exec_size;
    }

    std::uintptr_t search_pattern(std::uintptr_t base, size_t size, const char* ida_pattern) {
        std::uint8_t pattern[256];
        char mask[256];
        size_t pattern_size = 0;

        const char* ptr = ida_pattern;
        while (*ptr) {
            if (*ptr == ' ') {
                ptr++;
                continue;
            }

            if (*ptr == '?') {
                mask[pattern_size] = '?';
                pattern[pattern_size++] = 0;
                ptr++;

                if (*ptr == '?') ptr++;
            }
            else {
                char byte_str[3] = { ptr[0], ptr[1], 0 };
                pattern[pattern_size] = static_cast<std::uint8_t>(external_functions::km_strtoul(byte_str, nullptr, 16));
                mask[pattern_size++] = 'x';
                ptr += 2;
            }

            if (*ptr == ' ') ptr++;
        }

        mask[pattern_size] = 0;

        for (size_t i = 0; i < pattern_size; i++) {
            if (mask[i] == '?') mask[i] = '?';
            else mask[i] = 'x';
        }

        return private_sig_scan(base, size, pattern, mask);
    }

    std::uintptr_t scan_ida_pattern(const char* ida_pattern) {
        std::uint64_t text_base = 0;
        std::uint64_t text_size = 0;

        if (!next_exec_section(&text_base, &text_size))
            return 0;

        return search_pattern(text_base, text_size, ida_pattern);
    }

    bool pattern_check(const char* data, const char* pattern, const char* mask)
    {
        size_t len = strlen(mask);

        for (size_t i = 0; i < len; i++)
        {
            if (data[i] == pattern[i] || mask[i] == '?')
                continue;
            else
                return false;
        }

        return true;
    }

    PVOID get_pattern_private(PVOID base, int length, const char* pattern, const char* mask)
    {
        length -= static_cast<int>(strlen(mask));
        for (auto i = 0; i <= length; ++i) {
            const auto* data = static_cast<char*>(base);
            const auto* address = &data[i];
            if (pattern_check(address, pattern, mask))
                return PVOID(address);
        }
        return nullptr;
    }

    PVOID get_pattern(PVOID base, const char* pattern, const char* mask)
    {
        PVOID match = nullptr;

        auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
        auto* sections = IMAGE_FIRST_SECTION(headers);

        for (auto i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
            auto* section = &sections[i];
            if ('EGAP' == *reinterpret_cast<PINT>(section->Name) || memcmp(section->Name, ".text", 5) == 0) {
                match = get_pattern_private(static_cast<char*>(base) + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
                if (match)
                    break;
            }
        }
        return match;
    }
}

namespace io_caller {
    inline NTSTATUS io_create_device(PDRIVER_OBJECT DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DEVICE_TYPE DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, PDEVICE_OBJECT* DeviceObject)
    {
        static auto export_address = 0ull;

        if (!export_address)
        {
            export_address = export_handler::get_export("IoCreateDevice");
            if (!export_address)
            {
                DbgPrint("[Impala (EXP)] failed to retrieve io_create_device");
                return STATUS_NOT_FOUND;
            }
        }

        using function_t = NTSTATUS(*)(PDRIVER_OBJECT, ULONG, PUNICODE_STRING, DEVICE_TYPE, ULONG, BOOLEAN, PDEVICE_OBJECT*);
        return reinterpret_cast<function_t>(export_address)(DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, DeviceObject);
    }

    inline NTSTATUS io_create_symbolic_link(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName)
    {
        static auto export_address = 0ull;

        if (!export_address)
        {
            export_address = export_handler::get_export("IoCreateSymbolicLink");
            if (!export_address)
            {
                DbgPrint("[Impala (EXP)] failed to retrieve io_create_symbolic_link");
                return STATUS_NOT_FOUND;
            }
        }

        using function_t = NTSTATUS(*)(PUNICODE_STRING, PUNICODE_STRING);
        return reinterpret_cast<function_t>(export_address)(SymbolicLinkName, DeviceName);
    }

    inline void io_delete_device(PDEVICE_OBJECT DeviceObject)
    {
        static auto export_address = 0ull;

        if (!export_address)
        {
            export_address = export_handler::get_export("IoDeleteDevice");
            if (!export_address)
            {
                DbgPrint("[Impala (EXP)] failed to retrieve io_delete_device");
                return;
            }
        }

        using function_t = void(*)(PDEVICE_OBJECT);
        reinterpret_cast<function_t>(export_address)(DeviceObject);
    }


    inline NTSTATUS io_delete_symbolic_link(PUNICODE_STRING SymbolicLinkName)
    {
        static auto export_address = 0ull;

        if (!export_address)
        {
            export_address = export_handler::get_export("IoDeleteSymbolicLink");
            if (!export_address)
            {
                DbgPrint("[Impala (EXP)] failed to retrieve io_delete_symbolic_link");
                return STATUS_NOT_FOUND;
            }
        }

        using function_t = NTSTATUS(*)(PUNICODE_STRING);
        return reinterpret_cast<function_t>(export_address)(SymbolicLinkName);
    }
}

namespace rtl_caller {
    inline void rtl_init_unicode_string(PUNICODE_STRING DestinationString, PCWSTR SourceString)
    {
        static auto export_address = 0ull;

        if (!export_address)
        {
            export_address = export_handler::get_export("RtlInitUnicodeString");
            if (!export_address)
            {
                if (DestinationString)
                {
                    DestinationString->Buffer = (PWSTR)SourceString;
                    if (SourceString)
                    {
                        SIZE_T len = wcslen(SourceString) * sizeof(WCHAR);
                        DestinationString->Length = (USHORT)len;
                        DestinationString->MaximumLength = (USHORT)(len + sizeof(WCHAR));
                    }
                    else
                    {
                        DestinationString->Length = 0;
                        DestinationString->MaximumLength = 0;
                    }
                }
                return;
            }
        }

        using function_t = void(*)(PUNICODE_STRING, PCWSTR);
        reinterpret_cast<function_t>(export_address)(DestinationString, SourceString);
    }

    inline void rtl_zero_memory(PVOID Destination, SIZE_T Length)
    {
        static auto export_address = 0ull;

        if (!export_address)
        {
            export_address = export_handler::get_export("RtlZeroMemory");
            if (!export_address)
            {
                if (Destination && Length)
                {
                    __stosb((PUCHAR)Destination, 0, Length);
                }
                return;
            }
        }

        using function_t = void(*)(PVOID, SIZE_T);
        reinterpret_cast<function_t>(export_address)(Destination, Length);
    }

    inline SIZE_T rtl_compare_memory(const PVOID Source1, const PVOID Source2, SIZE_T Length)
    {
        static auto export_address = 0ull;

        if (!export_address)
        {
            export_address = export_handler::get_export("RtlCompareMemory");
            if (!export_address)
            {
                if (!Source1 || !Source2)
                    return 0;

                SIZE_T i = 0;
                PUCHAR s1 = (PUCHAR)Source1;
                PUCHAR s2 = (PUCHAR)Source2;

                while (i < Length && s1[i] == s2[i])
                    i++;

                return i;
            }
        }

        using function_t = SIZE_T(*)(const PVOID, const PVOID, SIZE_T);
        return reinterpret_cast<function_t>(export_address)(Source1, Source2, Length);
    }
}

namespace dbg_caller {
    template<typename... Args>
    inline ULONG dbg_print(const char* format, Args... args)
    {
        static auto export_address = 0ull;

        if (!export_address)
        {
            export_address = export_handler::get_export("DbgPrint");
            if (!export_address)
            {
                return 0;
            }
        }

        using function_t = ULONG(__cdecl*)(const char*, ...);
        return reinterpret_cast<function_t>(export_address)(format, args...);
    }
}

namespace ex_handler {
    inline PVOID ex_allocate_pool_with_tag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
    {
        static auto export_address = 0ull;
        if (!export_address)
        {
            export_address = export_handler::get_export("ExAllocatePoolWithTag");
            if (!export_address)
            {
                return nullptr;
            }
        }
        using function_t = PVOID(*)(POOL_TYPE, SIZE_T, ULONG);
        return reinterpret_cast<function_t>(export_address)(PoolType, NumberOfBytes, Tag);
    }

    inline PVOID ex_allocate_pool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
    {
        static auto export_address = 0ull;
        if (!export_address)
        {
            export_address = export_handler::get_export("ExAllocatePool");
            if (!export_address)
            {
                return nullptr;
            }
        }
        using function_t = PVOID(*)(POOL_TYPE, SIZE_T);
        return reinterpret_cast<function_t>(export_address)(PoolType, NumberOfBytes);
    }
    inline void ex_free_pool_with_tag(PVOID P, ULONG Tag)
    {
        static auto export_address = 0ull;
        if (!export_address)
        {
            export_address = export_handler::get_export("ExFreePoolWithTag");
            if (!export_address)
            {
                return;
            }
        }
        using function_t = void(*)(PVOID, ULONG);
        reinterpret_cast<function_t>(export_address)(P, Tag);
    }

    inline void ex_free_pool(PVOID P)
    {
        static auto export_address = 0ull;
        if (!export_address)
        {
            export_address = export_handler::get_export("ExFreePool");
            if (!export_address)
            {
                return;
            }
        }
        using function_t = void(*)(PVOID);
        reinterpret_cast<function_t>(export_address)(P);
    }
}

namespace memory_manager_caller {
    bool mm_set_page_protection(std::uint64_t virtual_address, size_t size, std::uint64_t protection) {
        static std::uint64_t fn_address = 0ull;
        if (!fn_address) {
            fn_address = byte_handler::scan_ida_pattern(("48 89 5C 24 ? 55 56 57 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 41 8B D8 4C 8B FA"));
            if (!fn_address)
                return static_cast<NTSTATUS>(-1);
        }

        using function_t = bool(__stdcall*)(std::uint64_t, size_t, std::uint64_t);
        return reinterpret_cast<function_t>(fn_address)(virtual_address, size, protection);
    }
    e_structures::physical_memory_range_t* mm_get_physical_memory_ranges() {
        static auto export_address = 0ull;
        if (!export_address) {
            export_address = export_handler::get_export("MmGetPhysicalMemoryRanges");
            if (!export_address) return nullptr;
        }

        using function_t = e_structures::physical_memory_range_t * (void);
        return reinterpret_cast<function_t*>(export_address)();
    }
    PHYSICAL_ADDRESS mm_get_physical_address(void* virtual_address) {
        static auto export_address = 0ull;
        if (!export_address) {
            export_address = export_handler::get_export("MmGetPhysicalAddress");
            if (!export_address) return { };
        }

        using function_t = PHYSICAL_ADDRESS(*)(void* virtual_address);
        return reinterpret_cast<function_t>(export_address)(virtual_address);
    }

    void* mm_allocate_independent_pages(size_t size) {
        static void* mm_allocate_independent_pages = nullptr;
        if (!mm_allocate_independent_pages) {
            std::uint64_t page_section_base;
            std::uint64_t page_section_size;
            if (!export_handler::get_section("PAGE", &page_section_base, &page_section_size)) {
                return { };
            }

            mm_allocate_independent_pages = reinterpret_cast<void*>(byte_handler::search_pattern(page_section_base, page_section_size,"4C 8B DC 49 89 5B ? 45 89 4B ? 4D 89 43"));
            if (!mm_allocate_independent_pages) {
                mm_allocate_independent_pages = reinterpret_cast<void*>(byte_handler::search_pattern(page_section_base, page_section_size,"48 8B C4 48 89 58 ? 44 89 48 ? 55"));
                if (!mm_allocate_independent_pages)
                    return {};
            }
        }

        if (!mm_allocate_independent_pages)
            return nullptr;

        using function_t = void* (std::uint64_t, int, std::uint64_t, unsigned int);
        return reinterpret_cast<function_t*>(mm_allocate_independent_pages)(size, -1, 0, 0);
    }

    void mm_free_independent_pages(std::uint64_t independent_pages, size_t size) {
        static void* mm_free_independent_pages = nullptr;
        if (!mm_free_independent_pages) {
            std::uint64_t page_section_base;
            std::uint64_t page_section_size;
            if (!export_handler::get_section("PAGE", &page_section_base, &page_section_size))
                return;

            mm_free_independent_pages = reinterpret_cast<void*>(byte_handler::search_pattern(page_section_base, page_section_size,"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 48 83 65 ? ? BE"));
            if (!mm_free_independent_pages)
                return;
        }

        if (!mm_free_independent_pages)
            return;

        using function_t = void(std::uint64_t, int);
        reinterpret_cast<function_t*>(mm_free_independent_pages)(independent_pages, size);
    }

    char mi_make_page_bad(e_structures::mmpfn_t* pfn_entry, char lock) {
        static void* mi_make_page_bad = nullptr;
        if (!mi_make_page_bad) {
            mi_make_page_bad = reinterpret_cast<void*>(byte_handler::scan_ida_pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B F2 8B EA"));
            if (!mi_make_page_bad)
                return 0;
        }

        using function_t = char(__stdcall*)(e_structures::mmpfn_t*, char);
        return reinterpret_cast<function_t>(mi_make_page_bad)(pfn_entry, lock);
    }

    char mi_is_page_on_bad_list(e_structures::mmpfn_t* pfn_entry) {
        static void* mi_is_page_on_bad_list = nullptr;
        if (!mi_is_page_on_bad_list) {
            mi_is_page_on_bad_list = reinterpret_cast<void*>(byte_handler::scan_ida_pattern(("8A 41 ? 24 ? 3C ? 74")));
            if (!mi_is_page_on_bad_list)
                return 0;
        }

        using function_t = char(__stdcall*)(e_structures::mmpfn_t*);
        return reinterpret_cast<function_t>(mi_is_page_on_bad_list)(pfn_entry);
    }

    NTSTATUS mm_mark_physical_memory_as_bad(std::uint64_t physical_address, size_t size) {
        static std::uint64_t mm_mark_physical_memory_as_bad = 0ull;
        if (!mm_mark_physical_memory_as_bad) {
            mm_mark_physical_memory_as_bad = export_handler::get_export(("MmMarkPhysicalMemoryAsBad"));
            if (!mm_mark_physical_memory_as_bad)
                return STATUS_UNSUCCESSFUL;
        }

        PHYSICAL_ADDRESS phys_addr{ physical_address };
        ULARGE_INTEGER phys_size;
        phys_size.QuadPart = size;

        using mi_copy_on_write_t = NTSTATUS(__fastcall*)(PHYSICAL_ADDRESS*, ULARGE_INTEGER*);
        return reinterpret_cast<mi_copy_on_write_t>(mm_mark_physical_memory_as_bad)(&phys_addr, &phys_size);
    }

    __int64 __fastcall mi_lock_page_table_page(e_structures::mmpfn_t* pfn_entry, int a2) {
        static auto mi_lock_page_table_page = 0ull;
        if (!mi_lock_page_table_page) {
            mi_lock_page_table_page = byte_handler::scan_ida_pattern(("40 53 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ? 45 33 FF"));
            if (!mi_lock_page_table_page) {
                mi_lock_page_table_page = byte_handler::scan_ida_pattern(("40 53 56 57 41 54 41 56 41 57 48 83 EC"));
                if (!mi_lock_page_table_page) return 0;
            }
        }

        using function_t = __int64(e_structures::mmpfn_t*, int);
        return reinterpret_cast<function_t*>(mi_lock_page_table_page)(pfn_entry, a2);
    }

    void* mm_get_virtual_for_physical(std::uintptr_t phys_addr) {
        static auto export_address = 0ull;
        if (!export_address) {
            export_address = export_handler::get_export("MmGetVirtualForPhysical");
            if (!export_address) return nullptr;
        }

        using function_t = void* (*)(std::uintptr_t physical_address);
        return reinterpret_cast<function_t>(export_address)(phys_addr);
    }

    e_structures::mmpfn_t* mm_pfn_database() {
        static std::uint8_t* export_address = 0ull;
        if (!export_address) {
            export_address = reinterpret_cast<std::uint8_t*>(
                export_handler::get_export("KeCapturePersistentThreadState"));
            if (!export_address) return { };
        }

        while (export_address[0x0] != 0x48
            || export_address[0x1] != 0x8B
            || export_address[0x2] != 0x05)
            export_address++;

        return *reinterpret_cast<e_structures::mmpfn_t**>(
            &export_address[0x7] + *reinterpret_cast<std::int32_t*>(&export_address[0x3]));
    }
}

namespace ps_manager {
    std::uintptr_t ps_initial_system_process() {
        static auto export_address = 0ull;
        if (!export_address) {
            export_address = export_handler::get_export("PsInitialSystemProcess");
            if (!export_address) return 0;
        }

        return *reinterpret_cast<std::uintptr_t*>(export_address);
    }
}

namespace kernel_manager {
    std::uint32_t ke_get_current_processor_number() {
        static auto export_address = 0ull;
        if (!export_address) {
            export_address = export_handler::get_export("KeGetCurrentProcessorNumberEx");
            if (!export_address) return {};
        }

        using function_t = std::uint32_t(__int64);
        return reinterpret_cast<function_t*>(export_address)(0);
    }

    void ke_flush_entire_tb(bool invalidate, bool all_processors) {
        static auto export_address = 0ull;
        if (!export_address) {
            export_address = export_handler::get_export("KeFlushEntireTb");
            if (!export_address) return;
        }

        using function_t = void(*)(bool invalidate, bool all_processors);
        reinterpret_cast<function_t>(export_address)(invalidate, all_processors);
    }

    void ke_invalidate_all_caches() {
        static auto export_address = 0ull;
        if (!export_address) {
            export_address = export_handler::get_export("KeInvalidateAllCaches");
            if (!export_address) return;
        }

        using function_t = void(*)();
        reinterpret_cast<function_t>(export_address)();
    }

    void ke_flush_single_tb(std::uintptr_t address, bool all_processors, bool invalidate) {
        static auto export_address = 0ull;
        if (!export_address) {
            export_address = export_handler::get_export("KeFlushSingleTb");
            if (!export_address) return;
        }

        using function_t = void(*)(std::uintptr_t address, bool all_processors, bool invalidate);
        reinterpret_cast<function_t>(export_address)(address, all_processors, invalidate);
    }
}

namespace module_handler {

    struct function_entry
    {
        const char* module;
        const char* name;
        PVOID base_address;
        const char* signature;
        const char* mask;
        std::uint64_t cached_address;
    };

    bool get_module_address(const char* moduleName, PVOID* handle)
    {
        ULONG size = 0;

        auto status = external_functions::ZwQuerySystemInformation(11, &size, 0, &size);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
            return 0;

        auto* moduleList = static_cast<e_structures::PSYSTEM_MODULE_INFORMATION>(ex_handler::ex_allocate_pool_with_tag(NonPagedPool, (size * 2), 'SOAR'));
        if (!moduleList)
            return 0;

        status = external_functions::ZwQuerySystemInformation(11, moduleList, size, nullptr);
        if (!NT_SUCCESS(status))
            goto end;

        for (auto i = 0; i < moduleList->Count; i++) {
            auto module = moduleList->Module[i];
            if (strstr(module.Name, moduleName)) {
				dbg_caller::dbg_print("[Impala] retrieved module address for %s : %llp\n", moduleName, module.BaseAddress);
                *handle = module.BaseAddress;
                break;
            }
        }
        ex_handler::ex_free_pool_with_tag(moduleList, 'SOAR');
        return 1;
    end:
        ex_handler::ex_free_pool_with_tag(moduleList, 'SOAR');
		dbg_caller::dbg_print("[Impala] failed to retrieve module address for %s\n", moduleName);
        return 0;
    }

    inline function_entry g_functions[] = {
        { "partmgr.sys", "PmFilterDeviceControl",    nullptr,   "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x41\x56\x41\x57\x48\x83\xEC\x00\x4C\x8B\x79", "xxxx?xxxx?xxxx?xxxxxxxx?xxx", 0},
        { "storport.sys", "RaDriverDeviceControlIrp",    nullptr,   "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x00\x48\x8B\xFA\x48\x8B\xF1\x48\x8B\x0D\x00\x00\x00\x00\x48\x8D\x2D\x00\x00\x00\x00\x48\x3B\xCD\x74\x00\x8B\x41\x00\xA8\x00\x0F\x85\x00\x00\x00\x00\xC6\x87\x00\x00\x00\x00\x00\x48\x8B\x4E\x00\x00\x00\x3D\x00\x00\x00\x00\x75\x00\x48\x8B\xD7\xE8\x00\x00\x00\x00\x8B\xD8\x48\x8B\x0D\x00\x00\x00\x00\x48\x3B\xCD\x74\x00\x8B\x41\x00\xA8\x00\x0F\x85\x00\x00\x00\x00\x48\x8B\x6C\x24\x00\x8B\xC3\x48\x8B\x5C\x24\x00\x48\x8B\x74\x24\x00\x48\x83\xC4\x00\x5F\xC3\x00\x3D\x00\x00\x00\x00\x0F\x85", "xxxx?xxxx?xxxx?xxxx?xxxxxxxxx????xxx????xxxx?xx?x?xx????xx?????xxx???x????x?xxxx????xxxxx????xxxx?xx?x?xx????xxxx?xxxxxx?xxxx?xxx?xx?x????xx", 0},
    };

    __forceinline bool starts_with(const char* full, const char* prefix)
    {
        if (!full || !prefix)
            return false;

        while (*prefix)
        {
            if (*full++ != *prefix++)
                return false;
        }

        return true;
    }

    bool populate_list(const char* shortName, std::uint64_t* base_address)
    {
        if (!shortName)
            return false;

        bool matched = false;

        for (auto& entry : g_functions)
        {
            if (!entry.module) {
				dbg_caller::dbg_print("[Impala] module name is null, skipping...\n");
                continue;
            }

            if (starts_with(entry.module, shortName))
            {
				dbg_caller::dbg_print("[Impala] located module: %s\n", entry.module);
                PVOID base_address_local = 0;
                if (!module_handler::get_module_address(entry.module, &base_address_local))
                    return false;
                dbg_caller::dbg_print("[Impala] retrieved population result base : %llp\n", base_address_local);
                entry.base_address = (PVOID)base_address_local;
				*base_address = (std::uint64_t)base_address_local;
                matched = true;
            }

			dbg_caller::dbg_print("[Impala] finished processing module: %s\n", entry.module);
        }

        return matched;
    }

    bool retrieve_function(const char* shortName, std::uint64_t* storage)
    {
        if (!shortName)
            return false;

        bool matched = false;

        for (auto& entry : g_functions)
        {
            if (!entry.name)
                continue;

            if (starts_with(entry.name, shortName))
            {
                PVOID returnAddress = byte_handler::get_pattern(entry.base_address, entry.signature, entry.mask);
                if (returnAddress != nullptr)
                    *storage = (std::uint64_t)returnAddress;
				dbg_caller::dbg_print("[Impala] retrieved function %s address : %llp\n", entry.name, returnAddress);
                matched = true;
                return matched;
            }
        }
		dbg_caller::dbg_print("[Impala] failed to retrieve function %s\n", shortName);
        return matched;
    }
}