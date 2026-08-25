#pragma once
#include <includes/includes.hxx>
#include <definitions/definitions.hxx>
#include <handlers/generative/gen.hxx>

namespace rcv_handler {
	NTSTATUS SmartRcvDriveDataIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (request.BufferLength >= sizeof(SENDCMDOUTPARAMS))
			{
				PSENDCMDOUTPARAMS cmdParams = (PSENDCMDOUTPARAMS)request.Buffer;
				e_structures::PIDSECTOR idSector = (e_structures::PIDSECTOR)cmdParams->bBuffer;

				PCHAR serial = idSector->sSerialNumber;
				SIZE_T length = strlen(serial);

				PIDENTIFY_DEVICE_DATA identifyDeviceData = (PIDENTIFY_DEVICE_DATA)cmdParams->bBuffer;
				e_structures::WWN* pWwn = (e_structures::WWN*)&identifyDeviceData->WorldWideName;

				serial_gen::swap_wwn((PUCHAR)pWwn, 0, sizeof(e_structures::WWN), gen_globals::wwn_entries);
				serial_gen::swap_serial(serial, length, gen_globals::serial_entries);
			}

			if (request.OldRoutine && irp->StackCount > 1)
			{
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}
		return STATUS_SUCCESS;
	}
}