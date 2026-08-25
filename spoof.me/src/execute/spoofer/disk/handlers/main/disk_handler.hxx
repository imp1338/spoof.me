#pragma once
#include <includes/definitions/definitions.hxx>
#include <handlers/memory/trampoline/trampoline.hxx>
#include <execute/spoofer/disk/caller/handle/handle_include.hxx>

e_structures::DRS handle_callers(PDEVICE_OBJECT pDeviceObj, PIRP pIrp, PCWSTR calledDriver)
{
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(pIrp);

	switch (ioc->Parameters.DeviceIoControl.IoControlCode)
	{
	//case IOCTL_DISK_GET_PARTITION_INFO_EX:
	//{
	//	//DebugPrint(skCrypt("          [DISK] IOCTL_DISK_GET_PARTITION_INFO_EX called "));
	//	io_swap_handler::change_ioc(ioc, pIrp, PartInfoExIoc);
	//	break;
	//}

	//case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
	//{
	//	//DebugPrint(skCrypt("          [DISK] IOCTL_DISK_GET_DRIVE_LAYOUT_EX called "));
	//	io_swap_handler::change_ioc(ioc, pIrp, PartLayoutIoc);
	//	break;
	//}

	case IOCTL_ATA_PASS_THROUGH_DIRECT:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_ATA_PASS_THROUGH_DIRECT called "));
		io_swap_handler::change_ioc(ioc, pIrp, ata_handler::AtaPassThroughDirectIoc);
		break;
	}

	case IOCTL_ATA_PASS_THROUGH:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_ATA_PASS_THROUGH called "));
		io_swap_handler::change_ioc(ioc, pIrp, ata_handler::AtaPassThroughIoc);
		break;
	}

	case IOCTL_ATA_MINIPORT:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_ATA_MINIPORT called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	case IOCTL_STORAGE_QUERY_PROPERTY:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_STORAGE_QUERY_PROPERTY called "));
		io_swap_handler::change_ioc(ioc, pIrp, storage_handler::StorageQueryPropertyIoc);
		//return STATUS_NOT_HANDLED;

		break;
	}

	case IOCTL_STORAGE_PROTOCOL_COMMAND:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_STORAGE_PROTOCOL_COMMAND called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	case SMART_RCV_DRIVE_DATA:
	{
		//DebugPrint(skCrypt("          [DISK] SMART_RCV_DRIVE_DATA called "));
		io_swap_handler::change_ioc(ioc, pIrp, rcv_handler::SmartRcvDriveDataIoc);
		break;
	}

	case IOCTL_SCSI_PASS_THROUGH_DIRECT:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_SCSI_PASS_THROUGH_DIRECT called "));
		io_swap_handler::change_ioc(ioc, pIrp, scsi_handler::ScsiPassThroughDirectIoc);
		break;
	}

	case IOCTL_SCSI_PASS_THROUGH_DIRECT_EX:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_SCSI_PASS_THROUGH_DIRECT_EX called "));
		io_swap_handler::change_ioc(ioc, pIrp, scsi_handler::ScsiPassThroughDirectExIoc);
		break;
	}

	case IOCTL_SCSI_PASS_THROUGH:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_SCSI_PASS_THROUGH called "));
		io_swap_handler::change_ioc(ioc, pIrp, scsi_handler::ScsiPassThroughIoc);
		break;
	}

	case IOCTL_SCSI_PASS_THROUGH_EX:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_SCSI_PASS_THROUGH_EX called "));
		io_swap_handler::change_ioc(ioc, pIrp, scsi_handler::ScsiPassThroughExIoc);
		break;
	}

	case IOCTL_IDE_PASS_THROUGH:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_IDE_PASS_THROUGH called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	case IOCTL_SCSI_MINIPORT:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_SCSI_MINIPORT called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	case IOCTL_SCSI_MINIPORT_IDENTIFY:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_SCSI_MINIPORT_IDENTIFY called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
	}

	case IOCTL_MPIO_PASS_THROUGH_PATH:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_MPIO_PASS_THROUGH_PATH called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	case IOCTL_MPIO_PASS_THROUGH_PATH_DIRECT:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_MPIO_PASS_THROUGH_PATH_DIRECT called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	//case IOCTL_MOUNTMGR_QUERY_POINTS:
	//{
	//	//DebugPrint(skCrypt("          [DISK] IOCTL_MOUNTMGR_QUERY_POINTS called "));
	//	return e_structures::DRS::STATUS_NOT_HANDLED;
	//	break;
	//}

	//case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
	//{
	//	//DebugPrint(skCrypt("          [DISK] IOCTL_MOUNTDEV_QUERY_UNIQUE_ID called "));
	//	return e_structures::DRS::STATUS_NOT_HANDLED;
	//	break;
	//}

	case IOCTL_DISK_PERFORMANCE:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_DISK_PERFORMANCE called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	case IOCTL_DISK_GET_LENGTH_INFO:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_DISK_GET_LENGTH_INFO called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	case IOCTL_DISK_GET_DRIVE_GEOMETRY:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_DISK_GET_DRIVE_GEOMETRY called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_DISK_GET_DRIVE_GEOMETRY_EX called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	case IOCTL_STORAGE_GET_DEVICE_NUMBER:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_STORAGE_GET_DEVICE_NUMBER called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}

	case IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER:
	{
		//DebugPrint(skCrypt("          [DISK] IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER called "));
		//return STATUS_NOT_HANDLED;
		break;
	}

	case NVME_PASS_THROUGH_SRB_IO_CODE:
	{
		//DebugPrint(skCrypt("          [DISK] NVME_PASS_THROUGH_SRB_IO_CODE called "));
		return e_structures::DRS::STATUS_NOT_HANDLED;
		break;
	}
	}

	return e_structures::DRS::STATUS_LEAVE_ALONE;
}