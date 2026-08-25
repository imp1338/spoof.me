#pragma once
#include <logging/print.hxx>
#include <execute/io/io_functionare.h>

namespace io_handler {
	inline bool handle_io_unicode() {
		rtl_caller::rtl_init_unicode_string(&i_definitions::i_device, IOCTL_DEVICE);
		rtl_caller::rtl_init_unicode_string(&i_definitions::i_symbolic, IOCTL_SYMBOLIC_LINK);

		if (!i_definitions::i_device.Buffer || !i_definitions::i_symbolic.Buffer) {
			log_error_simple("failed to initialize unicode strings for device or symbolic link");
			return false;
		}
		return true;
	}

	inline bool cleanup() {
		io_caller::io_delete_device(d_definitions::i_device_object);
		return io_caller::io_delete_symbolic_link(&i_definitions::i_symbolic);
	}

	inline bool setup_communication() {
		NTSTATUS status = io_caller::io_create_device(d_definitions::i_driver_object,0,&i_definitions::i_device,FILE_DEVICE_UNKNOWN,0,FALSE,&d_definitions::i_device_object);
		if (!NT_SUCCESS(status) || !d_definitions::i_device_object) {
			log_error_simple("failed to create device object");
			return false;
		}

		status = io_caller::io_create_symbolic_link(&i_definitions::i_symbolic, &i_definitions::i_device);
		if (!NT_SUCCESS(status)) {
			log_error_simple("failed to create symbolic link");
			return false;
		}
		return true;
	}

	inline bool setup_dispatch_routines() {
		if (!d_definitions::i_driver_object) {
			log_error_simple("driver object is null, cannot setup dispatch routines");
			return false;
		}
		d_definitions::i_driver_object->MajorFunction[IRP_MJ_CREATE] = io_request::io_dispatch_create;
		d_definitions::i_driver_object->MajorFunction[IRP_MJ_CLOSE] = io_request::io_dispatch_close;
		d_definitions::i_driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = io_request::io_dispatch_device_control;
		return true;
	}

	inline bool setup_io(PDRIVER_OBJECT dObject)
	{
		if (!handle_io_unicode())
			return 0;

		d_definitions::i_driver_object = dObject;

		if (!setup_communication())
			return 0;

		if (!setup_dispatch_routines())
			return 0;

		return true;
	}
}