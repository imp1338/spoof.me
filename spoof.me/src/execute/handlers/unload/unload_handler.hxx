#pragma once
#include <execute/spoofer/devices/device_handler.hxx>

namespace unload_handler {
	VOID unload_spoofer(PDRIVER_OBJECT DriverObject) {
		dbg_caller::dbg_print("[Impala] Unloading Impala.\n");

		io_caller::io_delete_symbolic_link(&i_definitions::i_symbolic);
		io_caller::io_delete_device(DriverObject->DeviceObject);

		exec_handler::unswap_irp(module_stub::i_partmgr_address, trampoline_stub::PmFilterDeviceControl);
	    exec_handler::unswap_irp(module_stub::i_storport_address, trampoline_stub::RaDriverDeviceControl);

		dbg_caller::dbg_print("[Impala] Impala unloaded successfully.\n");
	}

	bool setup_unload(PDRIVER_OBJECT DriverObject) {
		DriverObject->DriverUnload = unload_spoofer;
		return true;
	}
}