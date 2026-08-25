#include <handlers/io/io.hxx>
#include <execute/handlers/unload/unload_handler.hxx>
#include <execute/handlers/cpu/control_handler.hxx>

int entry(PDRIVER_OBJECT dObject)
{
	if (!unload_handler::setup_unload(dObject))
		return 0;

	dbg_caller::dbg_print("[Impala] successfully setup unload routine.\n");

	if (!export_handler::get_ntos_base())
		return 0;

	dbg_caller::dbg_print("[Impala] ntoskrnl base located at: 0x%p\n", e_definitions::i_ntos_base);

	if (!cpu_initialization::setup_cpu())
		return 0;

	dbg_caller::dbg_print("[Impala] CPU handler setup completed.\n");

	if (!manipulation::initialize())
		return 0;

	dbg_caller::dbg_print("[Impala] memory manipulation module initialized.\n");

	if (!io_handler::setup_io(dObject))
		return 0;

	dbg_caller::dbg_print("[Impala] io setup complete.\n");

	if (!device_handler::initialize())
		return 0;

	dbg_caller::dbg_print("[Impala] device handler setup successfully.\n");
	return 1;

}