#pragma once
#include <includes/includes.hxx>
#include <definitions/definitions.hxx>
#include <handlers/generative/gen.hxx>

namespace ata_handler {
	NTSTATUS AtaPassThroughDirectIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (request.BufferLength >= sizeof(ATA_PASS_THROUGH_DIRECT))
			{
				PATA_PASS_THROUGH_DIRECT pte = (PATA_PASS_THROUGH_DIRECT)request.Buffer;
				PIDENTIFY_DEVICE_DATA identifyDeviceData = (PIDENTIFY_DEVICE_DATA)pte->DataBuffer;

				PCHAR serial = (PCHAR)identifyDeviceData->SerialNumber + 1;
				size_t length = sizeof(identifyDeviceData->SerialNumber);
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

	NTSTATUS AtaPassThroughIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (request.BufferLength >= sizeof(ATA_PASS_THROUGH_EX))
			{
				PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
				ULONG offset = (ULONG)pte->DataBufferOffset;

				if (offset && offset < request.BufferLength)
				{
					PIDENTIFY_DEVICE_DATA pDeviceData = ((PIDENTIFY_DEVICE_DATA)((PBYTE)request.Buffer + offset));
					PCHAR serial = (PCHAR)pDeviceData->SerialNumber + 1;
					size_t length = sizeof(pDeviceData->SerialNumber);
					e_structures::WWN* pWwn = (e_structures::WWN*)&pDeviceData->WorldWideName;

					serial_gen::swap_wwn((PUCHAR)pWwn, 0, sizeof(e_structures::WWN), gen_globals::wwn_entries);
					serial_gen::swap_serial(serial, length, gen_globals::serial_entries);
				}
			}

			if (request.OldRoutine && irp->StackCount > 1)
			{
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}
		return STATUS_SUCCESS;
	}
}