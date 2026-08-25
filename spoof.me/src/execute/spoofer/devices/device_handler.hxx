#pragma once
#include <memory/trampoline/trampoline.hxx>
#include <execute/spoofer/disk/handlers/main/disk_handler.hxx>
#include <execute/spoofer/disk/caller/callbacks/callback_include.hxx>

namespace module_stub {
	std::uint64_t i_storport_base = 0;
	std::uint64_t i_partmgr_base = 0;
	std::uint64_t i_storport_address = 0;
	std::uint64_t i_partmgr_address = 0;
}

namespace trampoline_stub {
	e_structures::hook_state_t RaDriverDeviceControl = { 0 };
	e_structures::hook_state_t PmFilterDeviceControl = { 0 };
}

namespace device_handler {

	bool initialize() {
		dbg_caller::dbg_print("[Impala] Initializing device handler modules...\n");

		if (!mountmgr_irp_caller::hit_mountmgr()) {
			dbg_caller::dbg_print("[Impala] Failed to hook partmgr device control IRP\n");
			return false;
		}

		return true;
	}
}
