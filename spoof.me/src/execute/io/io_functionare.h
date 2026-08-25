#pragma once

namespace io_request {
	inline NTSTATUS io_dispatch_create(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}
	inline NTSTATUS io_dispatch_close(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}
	inline NTSTATUS io_dispatch_device_control(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
		PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
		NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

		switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case 0x800:
			break;
		}

		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}
}