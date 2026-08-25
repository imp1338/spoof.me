#include <handlers/generative/gen.hxx>
#include <handlers/memory/trampoline/trampoline.hxx>

namespace scsi_handlers {
	NTSTATUS ScsiMiniportIdentifyIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (MmIsAddressValid(context))
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			const auto data = (SENDCMDOUTPARAMS*)(request.Buffer);

			if (MmIsAddressValid(data))
			{
				const auto params = reinterpret_cast<SENDCMDOUTPARAMS*>(data->bBuffer + sizeof(SRB_IO_CONTROL));
				if (!MmIsAddressValid(params))
				{
					goto _end;
				}
				const auto info = reinterpret_cast<e_structures::IDINFO*>(params->bBuffer);
				if (!MmIsAddressValid(info))
				{
					goto _end;
				}

				auto serial = reinterpret_cast<char*>(info->sSerialNumber);
				if (!MmIsAddressValid(serial))
				{
					goto _end;
				}
				serial::modify_serial_value(serial, strlen(serial));
			}

		_end:
			if (request.OldRoutine && irp->StackCount > 1)
			{
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS ScsiMiniportIdentifyThroughIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (MmIsAddressValid(context))
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			const auto data = (SENDCMDINPARAMS*)(request.Buffer);

			if (MmIsAddressValid(data))
			{
				e_structures::SCSI_PASS_THROUGH_WITH_BUFFERS24* sptwb = (e_structures::SCSI_PASS_THROUGH_WITH_BUFFERS24*)data->bBuffer;
				if (MmIsAddressValid(sptwb)
					&& (sptwb->Spt.Cdb[0] == 0xa1 // NVME PASS THROUGH
						|| sptwb->Spt.Cdb[0] == 0xe4  // SCSI READ
						|| sptwb->Spt.Cdb[0] == 0xe6  // NVME READ
						)
					) {
					e_structures::NVME_IDENTIFY_DEVICE* nvmeIdentify = sptwb->Spt.DataBufferOffset == sizeof(*sptwb) ?
						(e_structures::NVME_IDENTIFY_DEVICE*)&sptwb->DataBuf :
						(e_structures::NVME_IDENTIFY_DEVICE*)((e_structures::SCSI_PASS_THROUGH_WITH_BUFFERS*)sptwb)->DataBuf;
					char serialBuf[21] = { 0 };
					if (!MmIsAddressValid(nvmeIdentify))
					{
						goto _end;
					}
					if (!MmIsAddressValid(nvmeIdentify->SerialNumber))
					{
						goto _end;
					}
					RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
					serial::modify_serial_value(serialBuf, sizeof(serialBuf));
					RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
				}
			}

		_end:
			if (request.OldRoutine && irp->StackCount > 1)
			{
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS ScsiMiniportIdentifyThroughExIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (MmIsAddressValid(context))
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			const auto data = (SENDCMDINPARAMS*)(request.Buffer);

			if (MmIsAddressValid(data))
			{
				e_structures::SCSI_PASS_THROUGH_WITH_BUFFERS_EX* sptwb = (e_structures::SCSI_PASS_THROUGH_WITH_BUFFERS_EX*)data->bBuffer;
				if (MmIsAddressValid(sptwb)
					&& (sptwb->Spt.Cdb[0] == 0xa1 // NVME PASS THROUGH
						|| sptwb->Spt.Cdb[0] == 0xe4 // SCSI READ
						|| sptwb->Spt.Cdb[0] == 0xe6 // NVME READ
						)
					) {
					e_structures::NVME_IDENTIFY_DEVICE* nvmeIdentify = (e_structures::NVME_IDENTIFY_DEVICE*)&sptwb->ucDataBuf;
					char serialBuf[21] = { 0 };
					if (!MmIsAddressValid(nvmeIdentify)) {
						goto _end;
					}
					if (!MmIsAddressValid(nvmeIdentify->SerialNumber)) {
						goto _end;
					}
					RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
					serial::modify_serial_value(serialBuf, sizeof(serialBuf));
					RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
				}
			}

		_end:
			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS ScsiMiniportIdentifyThroughDirectIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
		if (MmIsAddressValid(context)) {
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			const auto data = (SENDCMDINPARAMS*)(request.Buffer);

			if (MmIsAddressValid(data)) {
				SCSI_PASS_THROUGH_DIRECT* sptd = (SCSI_PASS_THROUGH_DIRECT*)data->bBuffer;
				if (MmIsAddressValid(sptd)
					&& (sptd->Cdb[0] == 0xa1 // NVME PASS THROUGH
						|| sptd->Cdb[0] == 0xe4 // SCSI READ
						|| sptd->Cdb[0] == 0xe6 // NVME READ
						)
					)
				{
					e_structures::NVME_IDENTIFY_DEVICE* nvmeIdentify = (e_structures::NVME_IDENTIFY_DEVICE*)sptd->DataBuffer;
					if (!MmIsAddressValid(nvmeIdentify)) {
						goto _end;
					}
					if (!MmIsAddressValid(nvmeIdentify->SerialNumber)) {
						goto _end;
					}
					char serialBuf[21] = { 0 };
					RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
					serial::modify_serial_value(serialBuf, sizeof(serialBuf));
					RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
				}
			}

		_end:
			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS ScsiMiniportIdentifyThroughDirectExIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
		if (MmIsAddressValid(context)) {
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			const auto data = (SENDCMDINPARAMS*)(request.Buffer);

			if (MmIsAddressValid(data)) {
				SCSI_PASS_THROUGH_DIRECT_EX* sptd = (SCSI_PASS_THROUGH_DIRECT_EX*)data->bBuffer;
				if (MmIsAddressValid(sptd)
					&& (sptd->Cdb[0] == 0xa1 // NVME PASS THROUGH
						|| sptd->Cdb[0] == 0xe4 // SCSI READ
						|| sptd->Cdb[0] == 0xe6 // NVME READ
						)
					)
				{
					e_structures::NVME_IDENTIFY_DEVICE* nvmeIdentify = (e_structures::NVME_IDENTIFY_DEVICE*)sptd->DataOutBuffer;
					if (!MmIsAddressValid(nvmeIdentify)) {
						goto _end;
					}
					if (!MmIsAddressValid(nvmeIdentify->SerialNumber)) {
						goto _end;
					}
					char serialBuf[21] = { 0 };
					RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
					serial::modify_serial_value(serialBuf, sizeof(serialBuf));
					RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
				}
			}

		_end:
			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS NvmePassthroughIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
		if (MmIsAddressValid(context)) {
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			e_structures::INTEL_NVME_PASS_THROUGH* data = (e_structures::INTEL_NVME_PASS_THROUGH*)(request.Buffer);

			if (MmIsAddressValid(data)) {
				e_structures::NVME_IDENTIFY_DEVICE* nvmeId = (e_structures::NVME_IDENTIFY_DEVICE*)data->DataBuffer;

				char serialBuf[21] = { 0 };
				RtlCopyMemory(serialBuf, nvmeId->SerialNumber, 20);
				serial::modify_serial_value(serialBuf, sizeof(serialBuf));
				RtlCopyMemory(nvmeId->SerialNumber, serialBuf, 20);
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS StorageQueryNamespaceIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
		if (MmIsAddressValid(context)) {
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			NVME_IDENTIFY_CONTROLLER_DATA* pNvmeNamespace = nullptr;
			e_structures::STORAGE_PROTOCOL_SPECIFIC_QUERY_WITH_BUFFER* spsq = (e_structures::STORAGE_PROTOCOL_SPECIFIC_QUERY_WITH_BUFFER*)request.Buffer;
			e_structures::PSTORAGE_DEVICE_DESCRIPTOR_DATA psdd = (e_structures::PSTORAGE_DEVICE_DESCRIPTOR_DATA)request.Buffer;
			PSTORAGE_PROTOCOL_DATA_DESCRIPTOR ptdd = (PSTORAGE_PROTOCOL_DATA_DESCRIPTOR)request.Buffer;
			if (!MmIsAddressValid(ptdd))
				goto _end;

			if (spsq->ProtocolData.DataType == NVMeDataTypeLogPage) {
				//RtlZeroMemory(spsq->DataBuffer, 512);
				goto _end;
			}
			else if (spsq->ProtocolData.DataType == NVMeDataTypeIdentify) {
				e_structures::nvme_id_ctrl* ctrl = (e_structures::nvme_id_ctrl*)spsq->DataBuffer;
				serial::modify_serial_value((char*)ctrl->sn, strlen((char*)ctrl->sn));	
				//FindFakeIEEE((IEEE*)ctrl->ieee);
				goto _end;
			}

			if (ptdd->ProtocolSpecificData.ProtocolType != ProtocolTypeNvme
				|| ptdd->ProtocolSpecificData.DataType != NVMeDataTypeIdentify) {

				if (psdd->desc.Size == (sizeof(*psdd) + psdd->desc.RawPropertiesLength)
					&& MmIsAddressValid((PVOID)((DWORD64)psdd->desc.RawDeviceProperties + psdd->desc.SerialNumberOffset))
					) {
					serial::modify_serial_value((char*)((DWORD64)psdd->desc.RawDeviceProperties + psdd->desc.SerialNumberOffset), strlen((char*)((DWORD64)psdd->desc.RawDeviceProperties + psdd->desc.SerialNumberOffset)));
				}
				goto _end;
			}

			pNvmeNamespace = (NVME_IDENTIFY_CONTROLLER_DATA*)((DWORD64)ptdd + ptdd->ProtocolSpecificData.ProtocolDataOffset + offsetof(STORAGE_PROPERTY_QUERY, AdditionalParameters));
			serial::modify_serial_value((char*)pNvmeNamespace->SN, sizeof(pNvmeNamespace->SN));
			//FindFakeIEEE((IEEE*)pNvmeNamespace->IEEE);

		_end:
			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS StorageQueryPropertyIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
		if (MmIsAddressValid(context)) {
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			PSTORAGE_PROTOCOL_DATA_DESCRIPTOR ptdd = (PSTORAGE_PROTOCOL_DATA_DESCRIPTOR)request.Buffer;
			if (MmIsAddressValid(ptdd) &&
				request.BufferLength == sizeof(STORAGE_DEVICE_DESCRIPTOR)
				) {
				DWORD64 protDataOffset = ptdd->ProtocolSpecificData.ProtocolDataOffset;
				DWORD64 protDataLen = ptdd->ProtocolSpecificData.ProtocolDataLength;
				char* pSerial = (char*)((DWORD64)ptdd + protDataOffset);

				if (ptdd->ProtocolSpecificData.ProtocolType != ProtocolTypeNvme
					|| ptdd->ProtocolSpecificData.DataType != NVMeDataTypeIdentify) {
					goto _end;
				}

				if (pSerial[12]) {
					serial::modify_serial_value(pSerial + 12, strlen(pSerial + 12));
				}
			}

		_end:
			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS AtaPassIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
		if (MmIsAddressValid(context)) {
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (!MmIsAddressValid(request.Buffer)) {
				goto _end;
			}
			if (request.BufferLength == (sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA))) {
				PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
				ULONG offset = (ULONG)pte->DataBufferOffset;
				if (MmIsAddressValid(pte) && offset && offset < request.BufferLength) {
					PIDENTIFY_DEVICE_DATA pDeviceData = ((PIDENTIFY_DEVICE_DATA)((PBYTE)request.Buffer + offset));
					PCHAR serial = (PCHAR)pDeviceData->SerialNumber;
					serial::modify_serial_value(serial, sizeof(serial));

					char serialBuf[31] = { 0 };
					memcpy(serialBuf, pDeviceData->CurrentMediaSerialNumber, 30);
					serial::modify_serial_value(serialBuf, sizeof(serialBuf));
					memcpy(pDeviceData->CurrentMediaSerialNumber, serialBuf, 30);

					e_structures::WWN* pWwn = (e_structures::WWN*)&pDeviceData->WorldWideName;
					serial::modify_wwn_value((PUCHAR)pWwn, 0, sizeof(e_structures::WWN));
				}
			}
			else if ((offsetof(e_structures::ATA_PASS_THROUGH_EX_WITH_BUFFERS, ucDataBuf) + SMART_LOG_SECTOR_SIZE) == request.BufferLength) {
				e_structures::ATA_PASS_THROUGH_EX_WITH_BUFFERS* ab = (e_structures::ATA_PASS_THROUGH_EX_WITH_BUFFERS*)request.Buffer;
				if (ab->apt.AtaFlags == ATA_FLAGS_DATA_IN
					&& ab->apt.DataTransferLength == SMART_LOG_SECTOR_SIZE
					) {
					e_structures::ata_identify_device* aid = (e_structures::ata_identify_device*)((DWORD64)request.Buffer + ab->apt.DataBufferOffset);
					serial::modify_serial_value((char*)aid->serial_no, sizeof(aid->serial_no));
				}
			}

		_end:
			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS AtaPassDirectIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
		if (MmIsAddressValid(context)) {
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (request.BufferLength == (sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA))) {
				PATA_PASS_THROUGH_DIRECT pte = (PATA_PASS_THROUGH_DIRECT)request.Buffer;
				if (MmIsAddressValid(pte) && pte->Length < request.BufferLength) {
					PIDENTIFY_DEVICE_DATA pDeviceData = (PIDENTIFY_DEVICE_DATA)pte->DataBuffer;
					PCHAR serial = (PCHAR)pDeviceData->SerialNumber;
					serial::modify_serial_value(serial, sizeof(pDeviceData->SerialNumber));

					char serialBuf[31] = { 0 };
					memcpy(serialBuf, pDeviceData->CurrentMediaSerialNumber, 30);
					serial::modify_serial_value(serialBuf, sizeof(pDeviceData->CurrentMediaSerialNumber));
					memcpy(pDeviceData->CurrentMediaSerialNumber, serialBuf, 30);

					e_structures::WWN* pWwn = (e_structures::WWN*)&pDeviceData->WorldWideName;
					serial::modify_wwn_value((PUCHAR)pWwn, 0, sizeof(e_structures::WWN));
				}
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS SmartDataIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
		if (MmIsAddressValid(context)) {
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (!MmIsAddressValid(request.Buffer)) {
				goto _end;
			}
			if (request.BufferLength == sizeof(SENDCMDOUTPARAMS)) {
				PCHAR serial = ((e_structures::PIDSECTOR)((PSENDCMDOUTPARAMS)request.Buffer)->bBuffer)->sSerialNumber;
				serial::modify_serial_value(serial, strlen(serial));
			}
			else if (request.BufferLength == (sizeof(SENDCMDOUTPARAMS) - 1 + SMART_LOG_SECTOR_SIZE)) {
				SENDCMDOUTPARAMS* outParam = (SENDCMDOUTPARAMS*)request.Buffer;
				e_structures::ata_identify_device* aid = (e_structures::ata_identify_device*)((DWORD64)outParam->bBuffer);
				if (MmIsAddressValid(aid) && MmIsAddressValid(aid->serial_no))
					serial::modify_serial_value((char*)aid->serial_no, sizeof(aid->serial_no));
			}

		_end:
			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS PartInfoIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (MmIsAddressValid(context))
		{
			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (request.BufferLength == sizeof(PARTITION_INFORMATION_EX))
			{
				PPARTITION_INFORMATION_EX info = (PPARTITION_INFORMATION_EX)request.Buffer;
				if (MmIsAddressValid(info) && PARTITION_STYLE_GPT == info->PartitionStyle)
				{
					guid::generate_guid(&info->Gpt.PartitionId, guid::stabalize(&info->Gpt.PartitionId));
				}
				else if (MmIsAddressValid(info) && info->PartitionStyle == PARTITION_STYLE_MBR)
				{
					guid::generate_guid(&info->Mbr.PartitionId, guid::stabalize(&info->Mbr.PartitionId));
				}
			}

			if (request.OldRoutine && irp->StackCount > 1)
			{
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS PartLayoutIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		//DebugPrint(skCrypt("in partmgr completion routine 1"));

		if (context)
		{

			e_structures::IOC_REQUEST request = *(e_structures::PIOC_REQUEST)context;
			ExFreePool(context);

			if (request.BufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX))
			{
				PDRIVE_LAYOUT_INFORMATION_EX info = (PDRIVE_LAYOUT_INFORMATION_EX)request.Buffer;
				if (MmIsAddressValid(info) && PARTITION_STYLE_GPT == info->PartitionStyle)
				{
					GUID* diskId = &info->Gpt.DiskId;
					DebugPrint("Partition GUID: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
						diskId->Data1,
						diskId->Data2,
						diskId->Data3,
						diskId->Data4[0], diskId->Data4[1],
						diskId->Data4[2], diskId->Data4[3], diskId->Data4[4], diskId->Data4[5], diskId->Data4[6], diskId->Data4[7]);

					guid::generate_guid(&info->Gpt.DiskId, guid::stabalize(&info->Gpt.DiskId));

					DebugPrint(skCrypt("Partition Count: %i", info->PartitionCount));

					for (DWORD i = 0; i < info->PartitionCount; i++)
					{
						if (info->PartitionEntry[i].PartitionStyle == PARTITION_STYLE_GPT)
						{
							GUID* partitionGuid = &info->PartitionEntry[i].Gpt.PartitionId;
							DebugPrint("Partition %u GUID: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
								i,
								partitionGuid->Data1,
								partitionGuid->Data2,
								partitionGuid->Data3,
								partitionGuid->Data4[0], partitionGuid->Data4[1],
								partitionGuid->Data4[2], partitionGuid->Data4[3], partitionGuid->Data4[4],
								partitionGuid->Data4[5], partitionGuid->Data4[6], partitionGuid->Data4[7]);

							guid::generate_guid(&info->PartitionEntry[i].Gpt.PartitionId, guid::stabalize(&info->PartitionEntry[i].Gpt.PartitionId));
							partitionGuid = &info->PartitionEntry[i].Gpt.PartitionId;
						}
						else
						{
							//DebugPrint(skCrypt("PartitionStyle not PARTITION_STYLE_GPT"));
						}
					}
				}
				else
				{
					//DebugPrint(skCrypt("info address not valid"));
				}
			}
			else
			{
				//DebugPrint(skCrypt("request.BufferLength size mismatch"));
			}

			if (request.OldRoutine && irp->StackCount > 1)
			{
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}
		else
		{
			//DebugPrint(skCrypt("context failed"));
		}

		return STATUS_SUCCESS;
	}
}

namespace private_disk_dispatcher {

	typedef enum DRS
	{
		STATUS_NONE,
		STATUS_NOT_HANDLED,
	};

	DRS handle_irp_calls(PDEVICE_OBJECT pDeviceObj, PIRP pIrp, PCWSTR calledDriver)
	{
		PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(pIrp);
		switch (ioc->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_DISK_GET_PARTITION_INFO_EX:
		{
			dbg_caller::dbg_print(("IOCTL_DISK_GET_PARTITION_INFO_EX1 called -> %S"), calledDriver);
			io_swap_handler::change_ioc(pIrp, scsi_handlers::PartInfoIoc);
			break;
		}

		case IOCTL_DISK_GET_PARTITION_INFO:
		{
			dbg_caller::dbg_print(("IOCTL_DISK_GET_PARTITION_INFO called -> %S"), calledDriver);
			break;
		}

		case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
		{
			dbg_caller::dbg_print(("IOCTL_DISK_GET_DRIVE_LAYOUT_EX1 called -> %S"), calledDriver);
			io_swap_handler::change_ioc(pIrp, scsi_handlers::PartLayoutIoc);
			break;
		}

		case IOCTL_ATA_PASS_THROUGH_DIRECT:
		{
			dbg_caller::dbg_print(("IOCTL_ATA_PASS_THROUGH_DIRECT called -> %S"), calledDriver);
			io_swap_handler::change_ioc(pIrp, scsi_handlers::AtaPassDirectIoc);
			break;
		}

		case IOCTL_ATA_PASS_THROUGH:
		{
			dbg_caller::dbg_print(("IOCTL_ATA_PASS_THROUGH called -> %S"), calledDriver);
			io_swap_handler::change_ioc(pIrp, scsi_handlers::AtaPassIoc);
			break;
		}

		case IOCTL_STORAGE_QUERY_PROPERTY:
		{
			dbg_caller::dbg_print(("IOCTL_STORAGE_QUERY_PROPERTY called -> %S"), calledDriver);
			auto pQuery = (PSTORAGE_PROPERTY_QUERY)pIrp->AssociatedIrp.SystemBuffer;
			if (MmIsAddressValid(pQuery)) {
				if (StorageDeviceProperty == pQuery->PropertyId
					|| StorageAdapterProtocolSpecificProperty == pQuery->PropertyId
					|| StorageDeviceProtocolSpecificProperty == pQuery->PropertyId) {
					if (PropertyStandardQuery == pQuery->QueryType) {
						io_swap_handler::change_ioc(pIrp, scsi_handlers::StorageQueryNamespaceIoc);
					}
					else {
						io_swap_handler::change_ioc(pIrp, scsi_handlers::StorageQueryPropertyIoc);
					}
				}
			}
			break;
		}

		case IOCTL_STORAGE_PROTOCOL_COMMAND:
		{
			dbg_caller::dbg_print(("IOCTL_STORAGE_PROTOCOL_COMMAND called -> %S"), calledDriver);
			return STATUS_NOT_HANDLED;
			break;
		}

		case SMART_RCV_DRIVE_DATA:
		{
			dbg_caller::dbg_print(("SMART_RCV_DRIVE_DATA called -> %S"), calledDriver);
			io_swap_handler::change_ioc(pIrp, scsi_handlers::SmartDataIoc);
			break;
		}

		case IOCTL_SCSI_PASS_THROUGH_DIRECT:
		{
			dbg_caller::dbg_print(("IOCTL_SCSI_PASS_THROUGH_DIRECT called -> %S"), calledDriver);
			io_swap_handler::change_ioc(pIrp, scsi_handlers::ScsiMiniportIdentifyThroughDirectIoc);
			break;
		}

		case IOCTL_SCSI_PASS_THROUGH:
		{
			dbg_caller::dbg_print(("IOCTL_SCSI_PASS_THROUGH called -> %S"), calledDriver);
			io_swap_handler::change_ioc(pIrp, scsi_handlers::ScsiMiniportIdentifyThroughIoc);
			break;
		}

		case IOCTL_SCSI_PASS_THROUGH_DIRECT_EX:
		{
			dbg_caller::dbg_print(("IOCTL_SCSI_PASS_THROUGH_DIRECT_EX called -> %S"), calledDriver);
			io_swap_handler::change_ioc(pIrp, scsi_handlers::ScsiMiniportIdentifyThroughDirectExIoc);
			break;
		}

		case IOCTL_SCSI_PASS_THROUGH_EX:
		{
			dbg_caller::dbg_print(("IOCTL_SCSI_PASS_THROUGH_EX called -> %S"), calledDriver);
			io_swap_handler::change_ioc(pIrp, scsi_handlers::ScsiMiniportIdentifyThroughExIoc);
			break;
		}

		case IOCTL_IDE_PASS_THROUGH:
		{
			dbg_caller::dbg_print(("IOCTL_IDE_PASS_THROUGH called -> %S"), calledDriver);
			return STATUS_NOT_HANDLED;
			break;
		}

		case IOCTL_SCSI_MINIPORT:
		{
			dbg_caller::dbg_print(("IOCTL_SCSI_MINIPORT called -> %S"), calledDriver);
			auto miniport_query = (SRB_IO_CONTROL*)(pIrp->AssociatedIrp.SystemBuffer);

			if (MmIsAddressValid(miniport_query)) {
				switch (miniport_query->ControlCode) {
				case IOCTL_SCSI_MINIPORT_IDENTIFY:
					io_swap_handler::change_ioc(pIrp, scsi_handlers::ScsiMiniportIdentifyIoc);
					break;
				case IOCTL_INTEL_NVME_PASS_THROUGH:
					io_swap_handler::change_ioc(pIrp, scsi_handlers::NvmePassthroughIoc);
					break;
					case NVME_PASS_THROUGH_SRB_IO_CODE:
					return STATUS_NOT_HANDLED;
				}
			}
			break;
		}

		}

		return STATUS_NONE;
	}
}

namespace context_swap {
	//NTSTATUS(*PmFilterDeviceControlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
	//NTSTATUS PmFilterDeviceControl(PDEVICE_OBJECT pDeviceObj, PIRP pIrp)
	//{
	//	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
	//	{
	//		DebugPrint(skCrypt("IRQL RAISED TO HAM"));
	//		return PmFilterDeviceControlOrig(pDeviceObj, pIrp);
	//	}

	//	if (ExGetPreviousMode() == KernelMode)
	//	{
	//		DebugPrint(skCrypt("Previous mode is kernelmode"));
	//		return PmFilterDeviceControlOrig(pDeviceObj, pIrp);
	//	}

	//	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(pIrp);
	//	switch (ioc->Parameters.DeviceIoControl.IoControlCode)
	//	{
	//	case IOCTL_DISK_GET_PARTITION_INFO_EX:
	//		pIrp->IoStatus.Information = 0;
	//		pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	//		IofCompleteRequest(pIrp, 0);
	//		return STATUS_NOT_SUPPORTED;
	//		break;
	//	case IOCTL_DISK_GET_PARTITION_INFO:
	//		pIrp->IoStatus.Information = 0;
	//		pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	//		IofCompleteRequest(pIrp, 0);
	//		return STATUS_NOT_SUPPORTED;
	//		break;
	//	case IOCTL_DISK_GET_DRIVE_LAYOUT:
	//		pIrp->IoStatus.Information = 0;
	//		pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	//		IofCompleteRequest(pIrp, 0);
	//		return STATUS_NOT_SUPPORTED;
	//		break;
	//	case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
	//		pIrp->IoStatus.Information = 0;
	//		pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	//		IofCompleteRequest(pIrp, 0);
	//		return STATUS_NOT_SUPPORTED;
	//		break;
	//	}
	//	return PmFilterDeviceControlOrig(pDeviceObj, pIrp);
	//}

	NTSTATUS(*PmFilterDeviceControlOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
	NTSTATUS PmFilterDeviceControl(PDEVICE_OBJECT pDeviceObj, PIRP pIrp)
	{
		if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		{
			dbg_caller::dbg_print("IRQL RAISED TO HAM");
			return PmFilterDeviceControlOrig(pDeviceObj, pIrp);
		}

		if (ExGetPreviousMode() == KernelMode)
		{
			dbg_caller::dbg_print(("Previous mode is kernelmode"));
			return PmFilterDeviceControlOrig(pDeviceObj, pIrp);
		}

		auto ReturnStatus = private_disk_dispatcher::handle_irp_calls(pDeviceObj, pIrp, L"partmgr.sys");
		if (ReturnStatus == private_disk_dispatcher::STATUS_NOT_HANDLED)
		{
			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IofCompleteRequest(pIrp, 0);
			return STATUS_NOT_SUPPORTED;
		}

		//IoSkipCurrentIrpStackLocation(pIrp);
		//return IoCallDriver(pDeviceObj, pIrp);
		return PmFilterDeviceControlOrig(pDeviceObj, pIrp);
	}

	NTSTATUS(*RaDriverDeviceControlIrpOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
	NTSTATUS RaDriverDeviceControlIrp(PDEVICE_OBJECT pDeviceObj, PIRP pIrp)
	{
		if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		{
			dbg_caller::dbg_print("IRQL RAISED TO HAM");
			return RaDriverDeviceControlIrpOrig(pDeviceObj, pIrp);
		}

		if (ExGetPreviousMode() == KernelMode)
		{
			dbg_caller::dbg_print(("Previous mode is kernelmode"));
			return RaDriverDeviceControlIrpOrig(pDeviceObj, pIrp);
		}

		auto ReturnStatus = private_disk_dispatcher::handle_irp_calls(pDeviceObj, pIrp, L"storport.sys");
		if (ReturnStatus == private_disk_dispatcher::STATUS_NOT_HANDLED)
		{
			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IofCompleteRequest(pIrp, 0);
			return STATUS_NOT_SUPPORTED;
		}

		//IoSkipCurrentIrpStackLocation(pIrp);
		//return IoCallDriver(pDeviceObj, pIrp);
		return RaDriverDeviceControlIrpOrig(pDeviceObj, pIrp);
	}


	/*NTSTATUS(*RaDriverDeviceControlIrpOrig)(PDEVICE_OBJECT pDeviceObj, PIRP pIrp);
	NTSTATUS RaDriverDeviceControlIrp(PDEVICE_OBJECT pDeviceObj, PIRP pIrp)
	{
		if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		{
			return RaDriverDeviceControlIrpOrig(pDeviceObj, pIrp);
		}

		if (ExGetPreviousMode() == KernelMode)
		{
			return RaDriverDeviceControlIrpOrig(pDeviceObj, pIrp);
		}
		PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(pIrp);
		if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY)
		{
			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IofCompleteRequest(pIrp, 0);
			return STATUS_NOT_SUPPORTED;
		}

		if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_PASS_THROUGH_DIRECT)
		{
			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IofCompleteRequest(pIrp, 0);
			return STATUS_NOT_SUPPORTED;
		}

		if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_PASS_THROUGH)
		{
			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IofCompleteRequest(pIrp, 0);
			return STATUS_NOT_SUPPORTED;
		}

		if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_PASS_THROUGH_DIRECT_EX)
		{
			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IofCompleteRequest(pIrp, 0);
			return STATUS_NOT_SUPPORTED;
		}

		if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_PASS_THROUGH_EX)
		{
			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IofCompleteRequest(pIrp, 0);
			return STATUS_NOT_SUPPORTED;
		}

		if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_IDE_PASS_THROUGH)
		{
			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IofCompleteRequest(pIrp, 0);
			return STATUS_NOT_SUPPORTED;
		}

		if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_MINIPORT)
		{
			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IofCompleteRequest(pIrp, 0);
			return STATUS_NOT_SUPPORTED;
		}
		return RaDriverDeviceControlIrpOrig(pDeviceObj, pIrp);
	}*/
}

namespace disk_handler {
	bool create_hook() {
		return false;
	}
}