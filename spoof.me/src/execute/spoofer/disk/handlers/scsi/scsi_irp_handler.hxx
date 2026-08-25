#pragma once
#include <includes/includes.hxx>
#include <definitions/definitions.hxx>
#include <handlers/generative/gen.hxx>

namespace scsi_handler {
	NTSTATUS ScsiPassThroughDirectIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (request.BufferLength >= sizeof(SCSI_PASS_THROUGH_DIRECT))
			{
				PSCSI_PASS_THROUGH_DIRECT pte = (PSCSI_PASS_THROUGH_DIRECT)request.Buffer;
				PVOID dataBuffer = pte->DataBuffer;

				e_structures::NVME_IDENTIFY_DEVICE* nvmeIdentify = (e_structures::NVME_IDENTIFY_DEVICE*)pte->DataBuffer;

				// --- SCSI VPD Unit Serial (Page 0x80) ---
				if (pte->Cdb[0] == 0x12 && (pte->Cdb[1] & 1) && pte->Cdb[2] == 0x80 && pte->DataTransferLength >= 4)
				{
					if (MmIsAddressValid(nvmeIdentify->SerialNumber))
					{
						if (strlen(nvmeIdentify->SerialNumber) > 5)
						{
							serial_gen::swap_serial(nvmeIdentify->SerialNumber, strlen(nvmeIdentify->SerialNumber), gen_globals::serial_entries);
						}
					}
				}

				// --- SCSI VPD Device ID (Page 0x83) ---
				if (pte->Cdb[0] == 0x12 && (pte->Cdb[1] & 1) && pte->Cdb[2] == 0x83 && pte->DataTransferLength >= 4)
				{
					PUCHAR buf = (PUCHAR)pte->DataBuffer;
					USHORT pageLen = (buf[2] << 8) | buf[3];
					ULONG offset = 4;

					while (offset + 4 <= pageLen + 4)
					{
						PUCHAR desc = buf + offset;
						UCHAR idType = desc[1] & 0x0F;
						UCHAR idLen = desc[3];

						if (offset + 4 + idLen > pageLen + 4)
						{
							break;
						}

						char id[128] = { 0 };
						ULONG copyLen = min(idLen, sizeof(id) - 1);

						RtlCopyMemory(id, desc + 4, copyLen);
						id[copyLen] = '\0';

						if (copyLen > 4)
						{
							serial_gen::swap_serial(id + 4, copyLen - 4, gen_globals::serial_entries);
							RtlCopyMemory(desc + 4 + 4, id + 4, copyLen - 4);
						}

						offset += 4 + idLen;
					}
				}
			}

			if (request.OldRoutine && irp->StackCount > 1)
			{
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}
		return STATUS_SUCCESS;
	}

	NTSTATUS ScsiPassThroughDirectExIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (request.BufferLength >= sizeof(SCSI_PASS_THROUGH_DIRECT_EX))
			{
				PSCSI_PASS_THROUGH_DIRECT_EX pte = (PSCSI_PASS_THROUGH_DIRECT_EX)request.Buffer;

				e_structures::NVME_IDENTIFY_DEVICE* nvmeIdentify = (e_structures::NVME_IDENTIFY_DEVICE*)pte->DataOutBuffer;
				PCHAR serial = (PCHAR)nvmeIdentify->SerialNumber + 4;

				if (strlen(serial) > 5)
				{
					serial_gen::swap_serial(serial, strlen(serial), gen_globals::serial_entries);
				}
			}

			if (request.OldRoutine && irp->StackCount > 1)
			{
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}
		return STATUS_SUCCESS;
	}

	NTSTATUS ScsiPassThroughIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (request.BufferLength >= sizeof(SCSI_PASS_THROUGH))
			{
				PSCSI_PASS_THROUGH desc = (PSCSI_PASS_THROUGH)request.Buffer;
				ULONG SerialNumber_offset = desc->DataBufferOffset;

				if (SerialNumber_offset && SerialNumber_offset < request.BufferLength) {
					PCHAR serial = (PCHAR)desc + SerialNumber_offset + 4;

					if (strlen(serial) > 5) {
						serial_gen::swap_serial(serial, strlen(serial), gen_globals::serial_entries);
					}
				}

				if (desc->Cdb[2] == SCSI_VPD_DEVICE_IDENTIFICATION)
				{
					PUCHAR dataBuffer = (PUCHAR)desc + desc->DataBufferOffset;
					ULONG dataLength = desc->DataTransferLength;

					if (dataBuffer && dataLength > 4)
					{
						PUCHAR vpdData = dataBuffer + 4;
						ULONG vpdDataLen = dataLength - 4;
						ULONG offset = 0;

						while (offset + 4 <= vpdDataLen)
						{
							UCHAR protocolCodeSet = vpdData[offset];
							UCHAR idTypeAssoc = vpdData[offset + 1];
							UCHAR idLength = vpdData[offset + 3];

							if (offset + 4 + idLength > vpdDataLen)
							{
								break;
							}

							CHAR idString[129] = { 0 };
							ULONG copyLen = (idLength < 128) ? idLength : 128;
							RtlCopyMemory(idString, &vpdData[offset + 4], copyLen);

							serial_gen::swap_serial(idString, idLength, gen_globals::serial_entries);
							RtlCopyMemory(&vpdData[offset + 4], idString, copyLen);

							offset += 4 + idLength;
						}
					}
				}
			}

			if (request.OldRoutine && irp->StackCount > 1)
			{
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}
		return STATUS_SUCCESS;
	}

	NTSTATUS ScsiPassThroughExIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (request.BufferLength >= sizeof(e_structures::SCSI_PASS_THROUGH_WITH_BUFFERS_EX))
			{
				e_structures::PSCSI_PASS_THROUGH_WITH_BUFFERS_EX pte = (e_structures::PSCSI_PASS_THROUGH_WITH_BUFFERS_EX)request.Buffer;
				e_structures::NVME_IDENTIFY_DEVICE* nvmeIdentify = (e_structures::NVME_IDENTIFY_DEVICE*)&pte->ucDataBuf;
				serial_gen::swap_serial((PCHAR)nvmeIdentify->SerialNumber, strlen((PCHAR)nvmeIdentify->SerialNumber), gen_globals::serial_entries);
			}

			if (request.OldRoutine && irp->StackCount > 1)
			{
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}
		return STATUS_SUCCESS;
	}
}