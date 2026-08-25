#pragma once
#include <includes/includes.hxx>
#include <definitions/definitions.hxx>
#include <handlers/generative/gen.hxx>
#include <stdio.h>

namespace storage_handler {
	NTSTATUS StorageQueryPropertyIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(irp);
			ExFreePool(context);

			PSTORAGE_ADAPTER_SERIAL_NUMBER adapterSerialNumber = (PSTORAGE_ADAPTER_SERIAL_NUMBER)request.Buffer;
			PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)request.Buffer;

			auto* nvmeDesc = (PSTORAGE_PROTOCOL_DATA_DESCRIPTOR)irp->AssociatedIrp.SystemBuffer;
			auto* psd = &nvmeDesc->ProtocolSpecificData;

			if (desc->BusType == BusTypeUsb)
			{
				return STATUS_SUCCESS;
			}


			if (psd->ProtocolType == ProtocolTypeNvme && psd->DataType == NVMeDataTypeIdentify && psd->ProtocolDataRequestValue == 0 && psd->ProtocolDataRequestSubValue == 1 && psd->ProtocolDataLength >= 0x70)
			{
				PUCHAR protocolData = (PUCHAR)psd + psd->ProtocolDataOffset;
				auto identifier = (PNVME_IDENTIFY_NAMESPACE_DATA)protocolData;
				PUCHAR nguid = identifier->NGUID;
				PUCHAR eui64 = identifier->EUI64;

				char nguidbuffer[16 * 2 + 1] = { 0 };
				for (int i = 0; i < 16; ++i)
				{
					sprintf_s(nguidbuffer + i * 2, 3, "%02X", nguid[i]);
				}
				serial_gen::swap_serial(nguidbuffer, strlen(nguidbuffer), gen_globals::serial_entries);

				char eui64buffer[8 * 2 + 1] = { 0 };
				for (int i = 0; i < 8; ++i)
				{
					sprintf_s(eui64buffer + i * 2, 3, "%02X", eui64[i]);
				}
				serial_gen::swap_serial(eui64buffer, strlen(eui64buffer), gen_globals::serial_entries);

				for (int i = 0; i < 16; ++i)
				{
					unsigned int byte;
					sscanf_s(nguidbuffer + i * 2, "%02X", &byte);
					identifier->NGUID[i] = (UCHAR)byte;
				}

				for (int i = 0; i < 8; ++i)
				{
					unsigned int byte;
					sscanf_s(nguidbuffer + i * 2, "%02X", &byte);
					identifier->EUI64[i] = (UCHAR)byte;
				}
			}

			if (wcslen(adapterSerialNumber->SerialNumber) > 5)
			{
				RtlZeroMemory(adapterSerialNumber->SerialNumber, sizeof(adapterSerialNumber->SerialNumber));
			}

			if (request.BufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR))
			{
				PUCHAR buffer = (PUCHAR)desc;

				if (28 + 20 <= request.BufferLength)
				{
					serial_gen::swap_wwn(buffer, 28, 20, gen_globals::wwn_entries);
				}

				ULONG SerialNumber_offset = desc->SerialNumberOffset;
				ULONG ProductId_offset = desc->ProductIdOffset;

				if (SerialNumber_offset && SerialNumber_offset < request.BufferLength)
				{
					PCHAR serial = (PCHAR)desc + SerialNumber_offset;

					UCHAR scsiBuffer[sizeof(SCSI_PASS_THROUGH) + 256] = { 0 };
					PSCSI_PASS_THROUGH scsiPassThrough = (PSCSI_PASS_THROUGH)scsiBuffer;

					scsiPassThrough->DataBufferOffset = sizeof(SCSI_PASS_THROUGH);
					PCHAR scsiSerial = (PCHAR)scsiPassThrough + scsiPassThrough->DataBufferOffset + 4;

					strcpy(scsiSerial, serial);
					size_t length = strlen(scsiSerial);

					serial_gen::swap_serial(scsiSerial, length, gen_globals::serial_entries);
					RtlCopyMemory(serial, scsiSerial, length);
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