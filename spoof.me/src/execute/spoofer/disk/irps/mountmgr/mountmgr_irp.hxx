#pragma once
#include <includes/includes.hxx>
#include <definitions/definitions.hxx>
#include <execute/spoofer/disk/handlers/main/disk_handler.hxx>

namespace mountmgr_globals
{
    e_structures::hook_state_t MountMgrDeviceControlIrp = { 0 };
    PVOID MountMgrDeviceControlIrpAddress = 0;
}

namespace mountmgr_irp_stub {
    NTSTATUS(*MountMgrDeviceControlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
    NTSTATUS MountMgrDeviceControl(PDEVICE_OBJECT pDeviceObj, PIRP pIrp)
    {
        if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        {
            return MountMgrDeviceControlOrig(pDeviceObj, pIrp);
        }
        auto ReturnStatus = handle_callers(pDeviceObj, pIrp, L"mountmgr");
        if (ReturnStatus == e_structures::DRS::STATUS_NOT_HANDLED)
        {
            pIrp->IoStatus.Information = 0;
            pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
            IofCompleteRequest(pIrp, 0);
            return STATUS_NOT_SUPPORTED;
        }
        return MountMgrDeviceControlOrig(pDeviceObj, pIrp);
    }
}

namespace mountmgr_irp_caller {
    bool hit_mountmgr()
    {
        PVOID MountmgrBase = 0;
        if (module_handler::get_module_address("mountmgr.sys", &MountmgrBase))
        {
            DebugPrint(("Retrieved mountmgr base : %llp"), MountmgrBase);
            mountmgr_globals::MountMgrDeviceControlIrpAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(MountmgrBase) + pdb_definitions::MountMgrDeviceControlRva);
            if (mountmgr_globals::MountMgrDeviceControlIrpAddress)
            {
                DebugPrint(("MountMgrDeviceControlIrp VA : %p"), trampoline_stub::MountMgrDeviceControlIrpAddress);
                exec_handler::swap_irp_context((uint64_t)mountmgr_globals::MountMgrDeviceControlIrpAddress, reinterpret_cast<void*>(mountmgr_irp_stub::MountMgrDeviceControl), &mountmgr_irp_stub::MountMgrDeviceControlOrig, &mountmgr_globals::MountMgrDeviceControlIrp);
            }
            else
            {
                DebugPrint(("Failed to get mountmgr function address"));
                return false;
            }
        }
        else
        {
            DebugPrint(("Failed to get mountmgr base"));
            return false;
        }
        return true;
    }
    void pullback_mountmgr()
    {
        exec_handler::unswap_irp((uint64_t)mountmgr_globals::MountMgrDeviceControlIrpAddress, mountmgr_globals::MountMgrDeviceControlIrp);
    }
}