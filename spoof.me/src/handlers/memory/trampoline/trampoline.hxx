#pragma once
#include <memory/manipulation/man_ip.hxx>

namespace exec_handler {
    std::uint64_t create_trampoline(std::uint64_t target_va, const std::uint8_t* original_bytes,
        size_t hook_size) {

        auto trampoline = reinterpret_cast<std::uint8_t*>(pages::alloc_page(0x100));
        if (!trampoline) {
            return 0;
        }

        if (!memory_manager_caller::mm_set_page_protection(reinterpret_cast<std::uint64_t>(trampoline),
            0x100, 0x40)) {
            pages::free_page(reinterpret_cast<std::uint64_t>(trampoline), 0x100);
            return 0;
        }

        if (!pages::hide_pages(trampoline, 0x100)) {
            pages::free_page(reinterpret_cast<std::uint64_t>(trampoline), 0x100);
            return 0;
        }

        memcpy(trampoline, original_bytes, hook_size);

        std::uint64_t jmp_back = target_va + hook_size;
        std::uint8_t jmp_back_code[shellcode_definitions::detour_size];
        memcpy(jmp_back_code, shellcode_definitions::detour_shellcode, shellcode_definitions::detour_size);
        memcpy(&jmp_back_code[2], &jmp_back, sizeof(std::uint64_t));
        memcpy(&trampoline[hook_size], jmp_back_code, shellcode_definitions::detour_size);

        return reinterpret_cast<std::uint64_t>(trampoline);
    }

    size_t calculate_hook_size(std::uint64_t target_pa, size_t min_size = shellcode_definitions::detour_size) {
        std::uint8_t buffer[64];
        if (!memory_handler::read_physical(target_pa, buffer, sizeof(buffer))) {
            return 0;
        }

        size_t total_len = 0;
        while (total_len < min_size && total_len < sizeof(buffer)) {
            e_structures::hde64s hde;
            external_functions::hde64_disasm(&buffer[total_len], &hde);
            if (hde.len == 0)
                break;
            total_len += hde.len;
        }

        return total_len;
    }

	template < typename org_t > bool swap_irp_context(std::uint64_t target_va, void* hook_function, org_t* original_function, e_structures::hook_state_t* out_state = nullptr) {
		DbgPrint(("[Impala] Creating hook at VA: 0x%llx\n"), target_va);
		if (!target_va || !hook_function || !original_function) {
			dbg_caller::dbg_print(("[Impala] Invalid parameters\n"));
			return false;
		}

		std::uint64_t target_pa = 0;
		//target_pa = (std::uint64_t)memory_manager_caller::mm_get_physical_address((void*)target_va).QuadPart;
		if (!pages::translate_linear(target_va, &target_pa)) {
			dbg_caller::dbg_print(("[Impala] Failed to translate VA 0x%llx to PA\n"), target_va);
			return false;
		}
		if (!target_pa) {
			dbg_caller::dbg_print(("[Impala] Translated PA is null for VA: 0x%llx\n"), target_va);
			return false;
		}

		dbg_caller::dbg_print(("[Impala] Target VA: 0x%llx -> PA: 0x%llx"), target_va, target_pa);

		std::uint8_t buffer[64];
		if (!memory_handler::read_physical(target_pa, buffer, sizeof(buffer))) {
			dbg_caller::dbg_print(("[Impala] Failed to read target bytes\n"));
			return false;
		}

		auto hook_size = calculate_hook_size(target_pa, shellcode_definitions::detour_size);
		if (hook_size < shellcode_definitions::detour_size) {
			dbg_caller::dbg_print(("[Impala] Hook size too small: %zu (need %zu)\n"),
				hook_size, shellcode_definitions::detour_size);
			return false;
		}

		dbg_caller::dbg_print(("[Impala] Hook size: %zu bytes\n"), hook_size);

		auto trampoline = create_trampoline(target_va, buffer, hook_size);
		if (!trampoline) {
			dbg_caller::dbg_print(("[Impala] Failed to create trampoline\n"));
			return false;
		}

		dbg_caller::dbg_print(("[Impala] Trampoline created at: 0x%llx\n"), trampoline);

		std::uint8_t hook_bytes[shellcode_definitions::detour_size];
		memcpy(hook_bytes, shellcode_definitions::detour_shellcode, shellcode_definitions::detour_size);
		auto hook_addr = reinterpret_cast<std::uint64_t>(hook_function);
		int32_t relative = static_cast<int32_t>(hook_addr - (target_va + shellcode_definitions::detour_size));
		memcpy(&hook_bytes[1], &relative, sizeof(std::uint64_t));

		if (!memory_handler::write_physical(target_pa, hook_bytes, shellcode_definitions::detour_size)) {
			dbg_caller::dbg_print(("[Impala] Failed to write hook bytes\n"));
			pages::free_page(trampoline, 0x100);
			return false;
		}

		if (hook_size > shellcode_definitions::detour_size) {
			std::uint8_t nops[32];
			memset(nops, 0x90, sizeof(nops));

			size_t nop_count = hook_size - shellcode_definitions::detour_size;
			if (!memory_handler::write_physical(target_pa + shellcode_definitions::detour_size, nops, nop_count)) {
				dbg_caller::dbg_print(("[Impala] Warning: Failed to write NOP padding\n"));
			}
		}

		pages::flush_caches(target_va);
		kernel_manager::ke_invalidate_all_caches();

		if (original_function) {
			*original_function = reinterpret_cast<org_t>(trampoline);
		}

		if (out_state) {
			memcpy(out_state->original_bytes, buffer, hook_size);
			out_state->hook_size = hook_size;
			out_state->trampoline = trampoline;
		}

		dbg_caller::dbg_print(("[Impala] Hook successfully installed at VA: 0x%llx (PA: 0x%llx)\n"),
			target_va, target_pa);
		return true;
	}

	bool unswap_irp(std::uint64_t target_va, e_structures::hook_state_t& state) {
		if (!target_va || !state.hook_size) {
			dbg_caller::dbg_print(("[Impala] Invalid parameters for unswap_irp\n"));
			return false;
		}

		std::uint64_t target_pa = 0;
		if (!pages::translate_linear(target_va, &target_pa)) {
			dbg_caller::dbg_print(("[Impala] Failed to translate VA 0x%llx to PA\n"), target_va);
			return false;
		}

		if (!memory_handler::write_physical(target_pa, state.original_bytes, state.hook_size)) {
			dbg_caller::dbg_print(("[Impala] Failed to restore original bytes at VA: 0x%llx (PA: 0x%llx)\n"),
				target_va, target_pa);
			return false;
		}

		if (state.trampoline) {
			std::uint8_t bytes = 0;
			memcpy(reinterpret_cast<void*>(state.trampoline), &bytes, state.hook_size);
		}

		pages::flush_caches(target_va);
		kernel_manager::ke_invalidate_all_caches();

		dbg_caller::dbg_print(("[Impala] Hook successfully removed at VA: 0x%llx (PA: 0x%llx)\n"),
			target_va, target_pa);
		return true;
	}
}

namespace io_swap_handler {

	bool change_ioc(PIO_STACK_LOCATION ioc, PIRP irp, PIO_COMPLETION_ROUTINE routine)
	{
		e_structures::PIOC_REQUEST request = (e_structures::PIOC_REQUEST)ExAllocatePool(NonPagedPool, sizeof(e_structures::IOC_REQUEST));
		if (request == 0) return false;

		request->Buffer = irp->AssociatedIrp.SystemBuffer;
		request->BufferLength = ioc->Parameters.DeviceIoControl.OutputBufferLength;
		request->OldContext = ioc->Context;
		request->OldRoutine = ioc->CompletionRoutine;

		ioc->Control = SL_INVOKE_ON_SUCCESS;
		ioc->Context = request;
		ioc->CompletionRoutine = routine;

		return true;
	};
}