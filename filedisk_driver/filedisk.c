/*
    This is a virtual disk driver for Windows NT/2000/XP that uses
    one or more files to emulate physical disks.
    Copyright (C) 1999-2004 Bo Brant閚.
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <ntddk.h>
#include <ntdddisk.h>
#include <ntddcdrm.h>
#include <ntverp.h>
#include <stdio.h>

//
// We include some stuff from newer DDK:s here so that one
// version of the driver for all versions of Windows can
// be compiled with the Windows NT 4.0 DDK.
//
#if (VER_PRODUCTBUILD < 2195)

#define FILE_DEVICE_MASS_STORAGE            0x0000002d
#define IOCTL_STORAGE_CHECK_VERIFY2         CTL_CODE(IOCTL_STORAGE_BASE, 0x0200, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000

#endif

#if (VER_PRODUCTBUILD < 2600)

#define IOCTL_DISK_GET_PARTITION_INFO_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0012, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_GET_LENGTH_INFO          CTL_CODE(IOCTL_DISK_BASE, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)

typedef enum _PARTITION_STYLE {
    PARTITION_STYLE_MBR,
    PARTITION_STYLE_GPT
} PARTITION_STYLE;

typedef unsigned __int64 ULONG64, *PULONG64;

typedef struct _PARTITION_INFORMATION_MBR {
    UCHAR   PartitionType;
    BOOLEAN BootIndicator;
    BOOLEAN RecognizedPartition;
    ULONG   HiddenSectors;
} PARTITION_INFORMATION_MBR, *PPARTITION_INFORMATION_MBR;

typedef struct _PARTITION_INFORMATION_GPT {
    GUID    PartitionType;
    GUID    PartitionId;
    ULONG64 Attributes;
    WCHAR   Name[36];
} PARTITION_INFORMATION_GPT, *PPARTITION_INFORMATION_GPT;

typedef struct _PARTITION_INFORMATION_EX {
    PARTITION_STYLE PartitionStyle;
    LARGE_INTEGER   StartingOffset;
    LARGE_INTEGER   PartitionLength;
    ULONG           PartitionNumber;
    BOOLEAN         RewritePartition;
    union {
        PARTITION_INFORMATION_MBR Mbr;
        PARTITION_INFORMATION_GPT Gpt;
    };
} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;

typedef struct _GET_LENGTH_INFORMATION {
    LARGE_INTEGER Length;
} GET_LENGTH_INFORMATION, *PGET_LENGTH_INFORMATION;

#endif // (VER_PRODUCTBUILD < 2600)

//
// We include some stuff from ntifs.h here so that
// the driver can be compiled with only the DDK.
//

#define TOKEN_SOURCE_LENGTH 8

typedef enum _TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
} TOKEN_TYPE;

typedef struct _TOKEN_SOURCE {
    CCHAR   SourceName[TOKEN_SOURCE_LENGTH];
    LUID    SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;

typedef struct _TOKEN_CONTROL {
    LUID            TokenId;
    LUID            AuthenticationId;
    LUID            ModifiedId;
    TOKEN_SOURCE    TokenSource;
} TOKEN_CONTROL, *PTOKEN_CONTROL;

typedef struct _SECURITY_CLIENT_CONTEXT {
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    PACCESS_TOKEN               ClientToken;
    BOOLEAN                     DirectlyAccessClientToken;
    BOOLEAN                     DirectAccessEffectiveOnly;
    BOOLEAN                     ServerIsRemote;
    TOKEN_CONTROL               ClientTokenControl;
} SECURITY_CLIENT_CONTEXT, *PSECURITY_CLIENT_CONTEXT;

#define PsDereferenceImpersonationToken(T)  \
            {if (ARGUMENT_PRESENT(T)) {     \
                (ObDereferenceObject((T))); \
            } else {                        \
                ;                           \
            }                               \
}

#define PsDereferencePrimaryToken(T) (ObDereferenceObject((T)))

NTKERNELAPI
VOID
PsRevertToSelf (
    VOID
);

NTKERNELAPI
NTSTATUS
SeCreateClientSecurity (
    IN PETHREAD                     Thread,
    IN PSECURITY_QUALITY_OF_SERVICE QualityOfService,
    IN BOOLEAN                      RemoteClient,
    OUT PSECURITY_CLIENT_CONTEXT    ClientContext
);

#define SeDeleteClientSecurity(C)  {                                           \
            if (SeTokenType((C)->ClientToken) == TokenPrimary) {               \
                PsDereferencePrimaryToken( (C)->ClientToken );                 \
            } else {                                                           \
                PsDereferenceImpersonationToken( (C)->ClientToken );           \
            }                                                                  \
}

NTKERNELAPI
VOID
SeImpersonateClient (
    IN PSECURITY_CLIENT_CONTEXT ClientContext,
    IN PETHREAD                 ServerThread OPTIONAL
);

NTKERNELAPI
TOKEN_TYPE
SeTokenType (
    IN PACCESS_TOKEN Token
);

//
// @Noema
//
NTSTATUS
CreateDriveLetter(IN WCHAR DriveLetter, IN ULONG DeviceNumber);

NTSTATUS
RemoveDriveLetter(IN WCHAR DriveLetter);




//
// For backward compatibility with Windows NT 4.0 by Bruce Engle.
//
#ifndef MmGetSystemAddressForMdlSafe
#define MmGetSystemAddressForMdlSafe(MDL, PRIORITY) MmGetSystemAddressForMdlPrettySafe(MDL)

PVOID
MmGetSystemAddressForMdlPrettySafe (
    PMDL Mdl
    )
{
    CSHORT  MdlMappingCanFail;
    PVOID   MappedSystemVa;

    MdlMappingCanFail = Mdl->MdlFlags & MDL_MAPPING_CAN_FAIL;

    Mdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;

    MappedSystemVa = MmGetSystemAddressForMdl(Mdl);

    if (MdlMappingCanFail == 0)
    {
        Mdl->MdlFlags &= ~MDL_MAPPING_CAN_FAIL;
    }

    return MappedSystemVa;
}
#endif

#include "filedisk.h"

#define PARAMETER_KEY           L"\\Parameters"

#define NUMBEROFDEVICES_VALUE   L"NumberOfDevices"

#define DEFAULT_NUMBEROFDEVICES 4

#define SECTOR_SIZE             512

#define TOC_DATA_TRACK          0x04

HANDLE dir_handle;

typedef struct _DEVICE_EXTENSION {
    BOOLEAN                     media_in_device;
    HANDLE                      file_handle;
    ANSI_STRING                 file_name;
    LARGE_INTEGER               file_size;
	LARGE_INTEGER				file_offset;
    BOOLEAN                     read_only;
    PSECURITY_CLIENT_CONTEXT    security_client_context;
    LIST_ENTRY                  list_head;
    KSPIN_LOCK                  list_lock;
    KEVENT                      request_event;
    PVOID                       thread_pointer;
    BOOLEAN                     terminate_thread;

	ULONG						device_index;
	PVOID						obj_target_disk;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

NTSTATUS
DriverEntry (
    IN PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING  RegistryPath
);

NTSTATUS
FileDiskCreateDevice (
    IN PDRIVER_OBJECT   DriverObject,
    IN ULONG            Number,
    IN DEVICE_TYPE      DeviceType
);

VOID
FileDiskUnload (
    IN PDRIVER_OBJECT   DriverObject
);

PDEVICE_OBJECT
FileDiskDeleteDevice (
    IN PDEVICE_OBJECT   DeviceObject
);

NTSTATUS
FileDiskCreateClose (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
FileDiskReadWrite (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
FileDiskDeviceControl (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

VOID
FileDiskThread (
    IN PVOID            Context
);

NTSTATUS
FileDiskOpenFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

NTSTATUS
FileDiskCloseFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
);

int swprintf(wchar_t *, const wchar_t *, ...);

#pragma code_seg("INIT")

NTSTATUS
DriverEntry (
    IN PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING  RegistryPath
    )
{
    UNICODE_STRING              parameter_path;
    RTL_QUERY_REGISTRY_TABLE    query_table[2];
    ULONG                       n_devices;
    NTSTATUS                    status;
    UNICODE_STRING              device_dir_name;
    OBJECT_ATTRIBUTES           object_attributes;
    ULONG                       n;
    USHORT                      n_created_devices;

    parameter_path.Length = 0;

    parameter_path.MaximumLength = RegistryPath->Length + sizeof(PARAMETER_KEY);

    parameter_path.Buffer = (PWSTR) ExAllocatePool(PagedPool, parameter_path.MaximumLength);

    if (parameter_path.Buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyUnicodeString(&parameter_path, RegistryPath);

    RtlAppendUnicodeToString(&parameter_path, PARAMETER_KEY);

    RtlZeroMemory(&query_table[0], sizeof(query_table));

    query_table[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED;
    query_table[0].Name = NUMBEROFDEVICES_VALUE;
    query_table[0].EntryContext = &n_devices;

    status = RtlQueryRegistryValues(
        RTL_REGISTRY_ABSOLUTE,
        parameter_path.Buffer,
        &query_table[0],
        NULL,
        NULL
        );

    ExFreePool(parameter_path.Buffer);

    if (!NT_SUCCESS(status))
    {
        KdPrint(("FileDisk: Query registry failed, using default values.\n"));
        n_devices = DEFAULT_NUMBEROFDEVICES;
    }

    RtlInitUnicodeString(&device_dir_name, DEVICE_DIR_NAME);

    InitializeObjectAttributes(
        &object_attributes,
        &device_dir_name,
        OBJ_PERMANENT,
        NULL,
        NULL
        );

    status = ZwCreateDirectoryObject(
        &dir_handle,
        DIRECTORY_ALL_ACCESS,
        &object_attributes
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ZwMakeTemporaryObject(dir_handle);

    for (n = 0, n_created_devices = 0; n < n_devices; n++)
    {
        status = FileDiskCreateDevice(DriverObject, n, FILE_DEVICE_DISK);

        if (NT_SUCCESS(status))
        {
            n_created_devices++;
        }
    }

    for (n = 0; n < n_devices; n++)
    {
        status = FileDiskCreateDevice(DriverObject, n, FILE_DEVICE_CD_ROM);

        if (NT_SUCCESS(status))
        {
            n_created_devices++;
        }
    }

    if (n_created_devices == 0)
    {
        ZwClose(dir_handle);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = FileDiskCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = FileDiskCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ]           = FileDiskReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = FileDiskReadWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FileDiskDeviceControl;

    DriverObject->DriverUnload = FileDiskUnload;

    return STATUS_SUCCESS;
}



NTSTATUS
FileDiskCreateDevice (
    IN PDRIVER_OBJECT   DriverObject,
    IN ULONG            Number,
    IN DEVICE_TYPE      DeviceType
    )
{
    WCHAR               device_name_buffer[MAXIMUM_FILENAME_LENGTH];
    UNICODE_STRING      device_name;
    NTSTATUS            status;
    PDEVICE_OBJECT      device_object;
    PDEVICE_EXTENSION   device_extension;
    HANDLE              thread_handle;

    ASSERT(DriverObject != NULL);

    if (DeviceType == FILE_DEVICE_CD_ROM)
    {
        swprintf(
            device_name_buffer,
            DEVICE_NAME_PREFIX L"Cd" L"%u",
            Number
            );
    }
    else
    {
        swprintf(
            device_name_buffer,
            DEVICE_NAME_PREFIX L"%u",
            Number
            );
    }

    RtlInitUnicodeString(&device_name, device_name_buffer);

    status = IoCreateDevice(
        DriverObject,
        sizeof(DEVICE_EXTENSION),
        &device_name,
        DeviceType,
        0,
        FALSE,
        &device_object
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    device_object->Flags |= DO_DIRECT_IO;

    device_extension = (PDEVICE_EXTENSION) device_object->DeviceExtension;

    device_extension->media_in_device = FALSE;
	device_extension->device_index = Number;

    if (DeviceType == FILE_DEVICE_CD_ROM)
    {
        device_object->Characteristics |= FILE_READ_ONLY_DEVICE;
        device_extension->read_only = TRUE;
    }

    InitializeListHead(&device_extension->list_head);

    KeInitializeSpinLock(&device_extension->list_lock);

    KeInitializeEvent(
        &device_extension->request_event,
        SynchronizationEvent,
        FALSE
        );

    device_extension->terminate_thread = FALSE;

    status = PsCreateSystemThread(
        &thread_handle,
        (ACCESS_MASK) 0L,
        NULL,
        NULL,
        NULL,
        FileDiskThread,
        device_object
        );

    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(device_object);
        return status;
    }

    status = ObReferenceObjectByHandle(
        thread_handle,
        THREAD_ALL_ACCESS,
        NULL,
        KernelMode,
        &device_extension->thread_pointer,
        NULL
        );

    if (!NT_SUCCESS(status))
    {
        ZwClose(thread_handle);

        device_extension->terminate_thread = TRUE;

        KeSetEvent(
            &device_extension->request_event,
            (KPRIORITY) 0,
            FALSE
            );

        IoDeleteDevice(device_object);

        return status;
    }

	ZwClose(thread_handle);

    return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")

VOID
FileDiskUnload (
    IN PDRIVER_OBJECT DriverObject
    )
{
	KdPrint((L"FileDiskUnload ===>> \n"));

    PDEVICE_OBJECT device_object;

    PAGED_CODE();

    device_object = DriverObject->DeviceObject;

    while (device_object)
    {
        device_object = FileDiskDeleteDevice(device_object);
    }

    ZwClose(dir_handle);

	KdPrint((L"FileDiskUnload <<=== \n"));
}

PDEVICE_OBJECT
FileDiskDeleteDevice (
    IN PDEVICE_OBJECT DeviceObject
    )
{
	KdPrint((L"FileDiskDeleteDevice ===>> \n"));

    PDEVICE_EXTENSION   device_extension;
    PDEVICE_OBJECT      next_device_object;

    PAGED_CODE();

    ASSERT(DeviceObject != NULL);

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    device_extension->terminate_thread = TRUE;

    KeSetEvent(
        &device_extension->request_event,
        (KPRIORITY) 0,
        FALSE
        );

    KeWaitForSingleObject(
        device_extension->thread_pointer,
        Executive,
        KernelMode,
        FALSE,
        NULL
        );

    ObDereferenceObject(device_extension->thread_pointer);

	//if (device_extension->obj_target_disk)
	//{
	//	ObDereferenceObject(device_extension->obj_target_disk);
	//}

    if (device_extension->security_client_context != NULL)
    {
        SeDeleteClientSecurity(device_extension->security_client_context);
        ExFreePool(device_extension->security_client_context);
    }

	next_device_object = DeviceObject->NextDevice;

    IoDeleteDevice(DeviceObject);

	KdPrint((L"FileDiskDeleteDevice <<=== \n"));

    return next_device_object;
}

NTSTATUS
FileDiskCreateClose (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = FILE_OPENED;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

#pragma code_seg()

NTSTATUS
FileDiskReadWrite (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION   device_extension;
    PIO_STACK_LOCATION  io_stack;

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (!device_extension->media_in_device)
    {
        Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_NO_MEDIA_IN_DEVICE;
    }

    io_stack = IoGetCurrentIrpStackLocation(Irp);

    if (io_stack->Parameters.Read.Length == 0)
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }

    IoMarkIrpPending(Irp);

    ExInterlockedInsertTailList(
        &device_extension->list_head,
        &Irp->Tail.Overlay.ListEntry,
        &device_extension->list_lock
        );

    KeSetEvent(
        &device_extension->request_event,
        (KPRIORITY) 0,
        FALSE
        );

    return STATUS_PENDING;
}

NTSTATUS
FileDiskDeviceControl (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PDEVICE_EXTENSION   device_extension;
    PIO_STACK_LOCATION  io_stack;
    NTSTATUS            status;

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    io_stack = IoGetCurrentIrpStackLocation(Irp);

    if (!device_extension->media_in_device &&
        io_stack->Parameters.DeviceIoControl.IoControlCode !=
        IOCTL_FILE_DISK_OPEN_FILE)
    {
        Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_NO_MEDIA_IN_DEVICE;
    }

    switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_FILE_DISK_OPEN_FILE:
        {
            SECURITY_QUALITY_OF_SERVICE security_quality_of_service;

            if (device_extension->media_in_device)
            {
                KdPrint(("FileDisk: IOCTL_FILE_DISK_OPEN_FILE: Media already opened\n"));

                status = STATUS_INVALID_DEVICE_REQUEST;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(OPEN_FILE_INFORMATION))
            {
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(OPEN_FILE_INFORMATION) + ((POPEN_FILE_INFORMATION)Irp->AssociatedIrp.SystemBuffer)->FileNameLength - sizeof(UCHAR)
				)
            {
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (device_extension->security_client_context != NULL)
            {
                SeDeleteClientSecurity(device_extension->security_client_context);
            }
            else
            {
                device_extension->security_client_context =
                    ExAllocatePool(NonPagedPool, sizeof(SECURITY_CLIENT_CONTEXT));
            }

            RtlZeroMemory(&security_quality_of_service, sizeof(SECURITY_QUALITY_OF_SERVICE));

            security_quality_of_service.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
            security_quality_of_service.ImpersonationLevel = SecurityImpersonation;
            security_quality_of_service.ContextTrackingMode = SECURITY_STATIC_TRACKING;
            security_quality_of_service.EffectiveOnly = FALSE;

            SeCreateClientSecurity(
                PsGetCurrentThread(),
                &security_quality_of_service,
                FALSE,
                device_extension->security_client_context
                );

            IoMarkIrpPending(Irp);

            ExInterlockedInsertTailList(
                &device_extension->list_head,
                &Irp->Tail.Overlay.ListEntry,
                &device_extension->list_lock
                );

            KeSetEvent(
                &device_extension->request_event,
                (KPRIORITY) 0,
                FALSE
                );

            status = STATUS_PENDING;

            break;
        }

    case IOCTL_FILE_DISK_CLOSE_FILE:
        {
            IoMarkIrpPending(Irp);

            ExInterlockedInsertTailList(
                &device_extension->list_head,
                &Irp->Tail.Overlay.ListEntry,
                &device_extension->list_lock
                );

            KeSetEvent(
                &device_extension->request_event,
                (KPRIORITY) 0,
                FALSE
                );

            status = STATUS_PENDING;

            break;
        }

    case IOCTL_FILE_DISK_QUERY_FILE:
        {
            POPEN_FILE_INFORMATION open_file_information;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(OPEN_FILE_INFORMATION) + device_extension->file_name.Length - sizeof(UCHAR))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            open_file_information = (POPEN_FILE_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            open_file_information->FileSize.QuadPart = device_extension->file_size.QuadPart;
            open_file_information->ReadOnly = device_extension->read_only;
            open_file_information->FileNameLength = device_extension->file_name.Length;

            RtlCopyMemory(
                open_file_information->FileName,
                device_extension->file_name.Buffer,
                device_extension->file_name.Length
                );

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(OPEN_FILE_INFORMATION) +
                open_file_information->FileNameLength - sizeof(UCHAR);

            break;
        }

    case IOCTL_DISK_CHECK_VERIFY:
    case IOCTL_CDROM_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY2:
        {
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            break;
        }

	case IOCTL_DISK_GET_MEDIA_TYPES:
	case IOCTL_STORAGE_GET_MEDIA_TYPES:
    case IOCTL_DISK_GET_DRIVE_GEOMETRY:
    case IOCTL_CDROM_GET_DRIVE_GEOMETRY:
	case IOCTL_DISK_UPDATE_DRIVE_SIZE:
        {
            PDISK_GEOMETRY  disk_geometry;
            ULONGLONG       length;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(DISK_GEOMETRY))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            disk_geometry = (PDISK_GEOMETRY) Irp->AssociatedIrp.SystemBuffer;

            length = device_extension->file_size.QuadPart;

            disk_geometry->MediaType = FixedMedia;
			disk_geometry->TracksPerCylinder = 2;
			disk_geometry->SectorsPerTrack = 32;
            disk_geometry->BytesPerSector = SECTOR_SIZE;
            disk_geometry->Cylinders.QuadPart = length / SECTOR_SIZE / disk_geometry->SectorsPerTrack / disk_geometry->TracksPerCylinder;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(DISK_GEOMETRY);

            break;
        }

    case IOCTL_DISK_GET_LENGTH_INFO:
        {
            PGET_LENGTH_INFORMATION get_length_information;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(GET_LENGTH_INFORMATION))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            get_length_information = (PGET_LENGTH_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            get_length_information->Length.QuadPart = device_extension->file_size.QuadPart;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);

        break;
        }

    case IOCTL_DISK_GET_PARTITION_INFO:
        {
            PPARTITION_INFORMATION  partition_information;
            ULONGLONG               length;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(PARTITION_INFORMATION))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            partition_information = (PPARTITION_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            length = device_extension->file_size.QuadPart;

            partition_information->StartingOffset.QuadPart = SECTOR_SIZE;

			// NOTE: 这里设置分区大小为实际分区大小，原（length - SECTOR_SIZE）导致exfat文件系统无法查看
			partition_information->PartitionLength.QuadPart = length; 

            partition_information->HiddenSectors = 1;
            partition_information->PartitionNumber = 0;
            partition_information->PartitionType = 0;
            partition_information->BootIndicator = FALSE;
            partition_information->RecognizedPartition = FALSE;
            partition_information->RewritePartition = FALSE;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION);

            break;
        }

    case IOCTL_DISK_GET_PARTITION_INFO_EX:
        {
            PPARTITION_INFORMATION_EX   partition_information_ex;
            ULONGLONG                   length;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(PARTITION_INFORMATION_EX))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            partition_information_ex = (PPARTITION_INFORMATION_EX) Irp->AssociatedIrp.SystemBuffer;

            length = device_extension->file_size.QuadPart;

            partition_information_ex->PartitionStyle = PARTITION_STYLE_MBR;
            partition_information_ex->StartingOffset.QuadPart = SECTOR_SIZE;

			// NOTE: 这里设置分区大小为实际分区大小，原（length - SECTOR_SIZE）导致exfat文件系统无法查看
			partition_information_ex->PartitionLength.QuadPart = length; 

            partition_information_ex->PartitionNumber = 0;
            partition_information_ex->RewritePartition = FALSE;
            partition_information_ex->Mbr.PartitionType = 0;
            partition_information_ex->Mbr.BootIndicator = FALSE;
            partition_information_ex->Mbr.RecognizedPartition = FALSE;
            partition_information_ex->Mbr.HiddenSectors = 1;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION_EX);

            break;
        }

    case IOCTL_DISK_IS_WRITABLE:
        {
            if (!device_extension->read_only)
            {
                status = STATUS_SUCCESS;
            }
            else
            {
                status = STATUS_MEDIA_WRITE_PROTECTED;
            }
            Irp->IoStatus.Information = 0;
            break;
        }

    case IOCTL_DISK_MEDIA_REMOVAL:
    case IOCTL_STORAGE_MEDIA_REMOVAL:
        {
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            break;
        }

    case IOCTL_CDROM_READ_TOC:
        {
            PCDROM_TOC cdrom_toc;

            if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(CDROM_TOC))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
                break;
            }

            cdrom_toc = (PCDROM_TOC) Irp->AssociatedIrp.SystemBuffer;

            RtlZeroMemory(cdrom_toc, sizeof(CDROM_TOC));

            cdrom_toc->FirstTrack = 1;
            cdrom_toc->LastTrack = 1;
            cdrom_toc->TrackData[0].Control = TOC_DATA_TRACK;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(CDROM_TOC);

            break;
        }

    case IOCTL_DISK_SET_PARTITION_INFO:
        {
            if (device_extension->read_only)
            {
                status = STATUS_MEDIA_WRITE_PROTECTED;
                Irp->IoStatus.Information = 0;
                break;
            }

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(SET_PARTITION_INFORMATION))
            {
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;

            break;
        }

    case IOCTL_DISK_VERIFY:
        {
            PVERIFY_INFORMATION verify_information;

            if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(VERIFY_INFORMATION))
            {
                status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
                break;
            }

            verify_information = (PVERIFY_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = verify_information->Length;

            break;
        }
	case IOCTL_DISK_UPDATE_PROPERTIES:
		{
			status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0;
			break;
		}

    default:
        {
            KdPrint((
                "FileDisk: Unknown IoControlCode %#x\n",
                io_stack->Parameters.DeviceIoControl.IoControlCode
                ));

            status = STATUS_INVALID_DEVICE_REQUEST;
            Irp->IoStatus.Information = 0;
        }
    }

    if (status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = status;

        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return status;
}

VOID
FileDiskThread (
    IN PVOID Context
    )
{
    PDEVICE_OBJECT      device_object;
    PDEVICE_EXTENSION   device_extension;
    PLIST_ENTRY         request;
    PIRP                irp;
    PIO_STACK_LOCATION  io_stack;
    PUCHAR              system_buffer;
    PUCHAR              buffer;
	LARGE_INTEGER		trans_offset;

    ASSERT(Context != NULL);

    device_object = (PDEVICE_OBJECT) Context;

    device_extension = (PDEVICE_EXTENSION) device_object->DeviceExtension;

    KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

    for (;;)
    {
        KeWaitForSingleObject(
            &device_extension->request_event,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );

        if (device_extension->terminate_thread)
        {
            PsTerminateSystemThread(STATUS_SUCCESS);
        }

        while (request = ExInterlockedRemoveHeadList(
            &device_extension->list_head,
            &device_extension->list_lock
            ))
        {
            irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

            io_stack = IoGetCurrentIrpStackLocation(irp);

            switch (io_stack->MajorFunction)
            {
            case IRP_MJ_READ:
                system_buffer = (PUCHAR) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
                if (system_buffer == NULL)
                {
                    irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    irp->IoStatus.Information = 0;
                    break;
                }
                buffer = (PUCHAR) ExAllocatePool(PagedPool, io_stack->Parameters.Read.Length);
                if (buffer == NULL)
                {
                    irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    irp->IoStatus.Information = 0;
                    break;
                }

				// 计算偏移量
				trans_offset.QuadPart = io_stack->Parameters.Read.ByteOffset.QuadPart + device_extension->file_offset.QuadPart;
				KdPrint(("0x%I64x = 0x%I64x + 0x%I64x \n", 
					trans_offset.QuadPart, 
					io_stack->Parameters.Read.ByteOffset.QuadPart, 
					device_extension->file_offset.QuadPart));
				KdPrint(("to read length: %d \n", io_stack->Parameters.Read.Length));

                ZwReadFile(
                    device_extension->file_handle,
                    NULL,
                    NULL,
                    NULL,
                    &irp->IoStatus,
                    buffer,
                    io_stack->Parameters.Read.Length,
                    &trans_offset,
                    NULL
                    );
                RtlCopyMemory(system_buffer, buffer, io_stack->Parameters.Read.Length);
                ExFreePool(buffer);
                break;

            case IRP_MJ_WRITE:
                if ((io_stack->Parameters.Write.ByteOffset.QuadPart +
                     io_stack->Parameters.Write.Length) >
                     device_extension->file_size.QuadPart)
                {
                    irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                    irp->IoStatus.Information = 0;
                }

				// 计算偏移量
				trans_offset.QuadPart = io_stack->Parameters.Write.ByteOffset.QuadPart + device_extension->file_offset.QuadPart;

                ZwWriteFile(
                    device_extension->file_handle,
                    NULL,
                    NULL,
                    NULL,
                    &irp->IoStatus,
                    MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority),
                    io_stack->Parameters.Write.Length,
                    &trans_offset,
                    NULL
                    );
                break;

            case IRP_MJ_DEVICE_CONTROL:
                switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
                {
                case IOCTL_FILE_DISK_OPEN_FILE:

                    SeImpersonateClient(device_extension->security_client_context, NULL);

                    irp->IoStatus.Status = FileDiskOpenFile(device_object, irp);

                    PsRevertToSelf();

					// @Noema
					if (NT_SUCCESS(irp->IoStatus.Status) )
					{
						if (KeGetCurrentIrql() <= PASSIVE_LEVEL)
						{
							RemoveDriveLetter(L'M' + device_extension->device_index);
						    CreateDriveLetter(L'M' + device_extension->device_index, device_extension->device_index);
						}
					}
					
                    break;

                case IOCTL_FILE_DISK_CLOSE_FILE:
                    irp->IoStatus.Status = FileDiskCloseFile(device_object, irp);

					// @Noema
					if (NT_SUCCESS(irp->IoStatus.Status))
					{
						if ( KeGetCurrentIrql() <= PASSIVE_LEVEL )
						{
							RemoveDriveLetter(L'M' + device_extension->device_index);
						}
					}

                    break;

                default:
                    irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
                }
                break;

            default:
                irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
            }

            IoCompleteRequest(
                irp,
                (CCHAR) (NT_SUCCESS(irp->IoStatus.Status) ?
                IO_DISK_INCREMENT : IO_NO_INCREMENT)
                );
        }
    }
}

#pragma code_seg("PAGE")

NTSTATUS
ObReferenceObjectByHandleEx(
	IN HANDLE file_handle,
	IN ACCESS_MASK DesiredAccess,
	OUT PFILE_OBJECT *file_object,
	OUT PDEVICE_OBJECT *device_object)

{
	NTSTATUS			status;
	PFILE_OBJECT		obj_file;

	PAGED_CODE();

	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	do 
	{
		status = ObReferenceObjectByHandle(
			file_handle,
			DesiredAccess,
			*IoFileObjectType,
			KernelMode,
			&obj_file,
			NULL
		);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("ObReferenceObjectByHandle failed, %#x \n", status));
			break;
		}

		if (file_object)
		{
			*file_object = obj_file;
		}

		if (device_object)
		{
			*device_object = IoGetRelatedDeviceObject(obj_file);
			if (!(*device_object))
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
		}

		status = STATUS_SUCCESS;

	} while (0);

	return status;
}

NTSTATUS
DeviceIoControlEx(
	IN PDEVICE_OBJECT device_object,
	IN ULONG IoControlCode,
	IN PVOID InBuffer,
	IN ULONG InBufferLength,
	OUT PVOID OutBuffer,
	IN ULONG OutBufferLength
)
{
	NTSTATUS					status;
	KEVENT						ioctl_event;
	PIRP						ioctl_irp;
	IO_STATUS_BLOCK				io_block;
	GET_LENGTH_INFORMATION		len_info;

	PAGED_CODE();

	if (device_object == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	do 
	{
		KeInitializeEvent(&ioctl_event, NotificationEvent, FALSE);

		ioctl_irp = IoBuildDeviceIoControlRequest(
			IoControlCode,
			device_object,
			InBuffer,
			InBufferLength,
			OutBuffer,
			OutBufferLength,
			FALSE,
			&ioctl_event,
			&io_block
		);
		if (ioctl_irp == NULL)
		{
			KdPrint(("IoBuildDeviceIoControlRequest failed \n"));
			status = STATUS_INVALID_PARAMETER;		// ???
			break;
		}

		status = IoCallDriver(device_object, ioctl_irp);
		if (status == STATUS_PENDING)
		{
			KeWaitForSingleObject(&ioctl_event, Executive, KernelMode, FALSE, NULL);
			status = io_block.Status;
		}
		if (!NT_SUCCESS(status))
		{
			break;
		}

		KdPrint(("IoBuildDeviceIoControlRequest io_block.Information: 0x%I64x, OutBufferLength: 0x%I64x \n", io_block.Information, OutBufferLength));

		status = STATUS_SUCCESS;

	} while (0);

	return status;
}

NTSTATUS
FileDiskOpenFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
	KdPrint(("FileDiskOpenFile ===>> \n"));

    PDEVICE_EXTENSION               device_extension;
    POPEN_FILE_INFORMATION          open_file_information;
    UNICODE_STRING                  ufile_name;
    NTSTATUS                        status;
    OBJECT_ATTRIBUTES               object_attributes;
    FILE_END_OF_FILE_INFORMATION    file_eof;
    FILE_BASIC_INFORMATION          file_basic;
    FILE_STANDARD_INFORMATION       file_standard;
    FILE_ALIGNMENT_INFORMATION      file_alignment;

    PAGED_CODE();

    ASSERT(DeviceObject != NULL);
    ASSERT(Irp != NULL);

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    open_file_information = (POPEN_FILE_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

    if (DeviceObject->DeviceType != FILE_DEVICE_CD_ROM)
    {
        device_extension->read_only = open_file_information->ReadOnly;
    }

    device_extension->file_name.Length = open_file_information->FileNameLength;
    device_extension->file_name.MaximumLength = open_file_information->FileNameLength;
    device_extension->file_name.Buffer = ExAllocatePool(NonPagedPool, open_file_information->FileNameLength);

    RtlCopyMemory(
        device_extension->file_name.Buffer,
        open_file_information->FileName,
        open_file_information->FileNameLength
        );

    status = RtlAnsiStringToUnicodeString(
        &ufile_name,
        &device_extension->file_name,
        TRUE
        );

    if (!NT_SUCCESS(status))
    {
		KdPrint(("RtlAnsiStringToUnicodeString failed %#x \n", status));
        ExFreePool(device_extension->file_name.Buffer);
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        return status;
    }

    InitializeObjectAttributes(
        &object_attributes,
        &ufile_name,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
        );

    status = ZwCreateFile(
        &device_extension->file_handle,
        device_extension->read_only ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
        &object_attributes,
        &Irp->IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        device_extension->read_only ? FILE_SHARE_READ : 0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_RANDOM_ACCESS |
        FILE_NO_INTERMEDIATE_BUFFERING |
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
        );

/*
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_NO_SUCH_FILE)
    {
		// 文件打开失败
		// 如果是只读或者文件大小为0，则打开文件失败
        if (device_extension->read_only || open_file_information->FileSize.QuadPart == 0)
        {
            ExFreePool(device_extension->file_name.Buffer);
            RtlFreeUnicodeString(&ufile_name);

            Irp->IoStatus.Status = STATUS_NO_SUCH_FILE;
            Irp->IoStatus.Information = 0;

            return STATUS_NO_SUCH_FILE;
        }
        else
        {
			// 创建镜像文件，支持读写
            status = ZwCreateFile(
                &device_extension->file_handle,
                GENERIC_READ | GENERIC_WRITE,
                &object_attributes,
                &Irp->IoStatus,
                &open_file_information->FileSize,
                FILE_ATTRIBUTE_NORMAL,
                0,
                FILE_OPEN_IF,
                FILE_NON_DIRECTORY_FILE |
                FILE_RANDOM_ACCESS |
                FILE_NO_INTERMEDIATE_BUFFERING |
                FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0
                );

            if (!NT_SUCCESS(status))
            {
				KdPrint(("ZwCreateFile create new file failed, %#x \n", status));
                ExFreePool(device_extension->file_name.Buffer);
                RtlFreeUnicodeString(&ufile_name);
                return status;
            }

            if (Irp->IoStatus.Information == FILE_CREATED)
            {
				// 创建成功，设置新创建的文件的大小
                file_eof.EndOfFile.QuadPart = open_file_information->FileSize.QuadPart;

                status = ZwSetInformationFile(
                    device_extension->file_handle,
                    &Irp->IoStatus,
                    &file_eof,
                    sizeof(FILE_END_OF_FILE_INFORMATION),
                    FileEndOfFileInformation
                    );

                if (!NT_SUCCESS(status))
                {
					KdPrint(("ZwSetInfomationFile filed, %#x \n", status));
                    ExFreePool(device_extension->file_name.Buffer);
                    RtlFreeUnicodeString(&ufile_name);
                    ZwClose(device_extension->file_handle);
                    return status;
                }
            }
        }
    }
    else if (!NT_SUCCESS(status))
*/

    if (!NT_SUCCESS(status))
    {
		char tmp[1024] = { 0 };
		RtlCopyMemory(tmp, device_extension->file_name.Buffer, device_extension->file_name.Length);
		KdPrint(("ZwCreateFile failed, %#x, %s \n", status, tmp));

        ExFreePool(device_extension->file_name.Buffer);
        RtlFreeUnicodeString(&ufile_name);
        return status;
    }

    RtlFreeUnicodeString(&ufile_name);

	char tmp[1024] = { 0 };
	RtlCopyMemory(tmp, device_extension->file_name.Buffer, device_extension->file_name.Length);
	KdPrint(("ZwCreateFile %s OK \n", tmp));

	// 
	// NOTE:
	// filedisk.exe传递物理磁盘的路径，实现挂载物理磁盘中的分区
	// 例如：
	// filedisk.exe /mount 0 \??\physicaldrive1 /ro M:
	// 该命令将以只读方式挂载磁盘physicaldrive1中的第一个能识别到的可用的分区，并挂载到M盘
	// filedisk.exe /mount 0 E:\example.dd /ro M:
	// 该命令将以只读方式挂载DD镜像文件example.dd到M盘
	//
	if (RtlCompareMemory(tmp, "\\??\\physicaldrive", 17) == 17)
	{
		//
		// 获取目标磁盘设备对象
		//

		PFILE_OBJECT		obj_file;

		ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

		status = ObReferenceObjectByHandleEx(
			device_extension->file_handle,
			GENERIC_READ,
			&obj_file,
			&device_extension->obj_target_disk);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("ObReferenceObjectByHandleEx failed, %#x \n", status));
			ExFreePool(device_extension->file_name.Buffer);
			ZwClose(device_extension->file_handle);
			return status;
		}

		// not required any more!!!
		ObDereferenceObject(obj_file);

		//
		// 获取目标磁盘设备信息（磁盘大小）
		//

		GET_LENGTH_INFORMATION		len_info;
		status = DeviceIoControlEx(
			device_extension->obj_target_disk,
			IOCTL_DISK_GET_LENGTH_INFO,
			NULL,
			0,
			&len_info,
			sizeof(len_info));
		if (!NT_SUCCESS(status))
		{
			ExFreePool(device_extension->file_name.Buffer);
			ZwClose(device_extension->file_handle);
			return status;
		}
		KdPrint(("disk size = 0x%I64x %dGB \n", len_info.Length.QuadPart, len_info.Length.QuadPart >> 30));

		DISK_GEOMETRY_EX disk_geometry = { 0 };
		status = DeviceIoControlEx(
			device_extension->obj_target_disk,
			IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
			NULL,
			0,
			&disk_geometry,
			sizeof(disk_geometry)
		);
		if (!NT_SUCCESS(status))
		{
			ExFreePool(device_extension->file_name.Buffer);
			ZwClose(device_extension->file_handle);
			return status;
		}
		KdPrint(("bytesofsize: 0x%I64x \n", disk_geometry.DiskSize.QuadPart));
		KdPrint(("bytespersector: 0x%I64x \n", disk_geometry.Geometry.BytesPerSector));
		KdPrint(("cylinders: 0x%I64x \n", disk_geometry.Geometry.Cylinders.QuadPart));
		KdPrint(("trackspercylinder: %d \n", disk_geometry.Geometry.TracksPerCylinder));
		KdPrint(("sectorspertrack: %d \n", disk_geometry.Geometry.SectorsPerTrack));

		PCHAR buffer = NULL;
		PDRIVE_LAYOUT_INFORMATION_EX drive_layout_info = NULL;
		PPARTITION_INFORMATION_EX part_info = NULL;

	    buffer = ExAllocatePool(NonPagedPool, 2048);
		RtlZeroMemory(buffer, 2048);

		status = DeviceIoControlEx(
			device_extension->obj_target_disk,
			IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			NULL,
			0,
			buffer,
			2048
		);
		if (NT_SUCCESS(status))
		{
			drive_layout_info = (PDRIVE_LAYOUT_INFORMATION_EX)buffer;
			KdPrint(("part style: %d \n", drive_layout_info->PartitionStyle));
			KdPrint(("part count: %d \n", drive_layout_info->PartitionCount));

			part_info = (PPARTITION_INFORMATION_EX)drive_layout_info->PartitionEntry;
			for (int idx=0; idx<drive_layout_info->PartitionCount && part_info; idx++, part_info++)
			{

				KdPrint(("part type = %d \n", part_info->Mbr.PartitionType));
				KdPrint(("part number = %d \n", part_info->PartitionNumber));
				KdPrint(("part start offset = 0x%I64x \n", part_info->StartingOffset.QuadPart));
				KdPrint(("part bytes = 0x%I64x, %dMB \n", part_info->PartitionLength.QuadPart, part_info->PartitionLength.QuadPart >> 20));

				if (part_info->PartitionStyle == PARTITION_STYLE_MBR)
				{
					if (part_info->Mbr.PartitionType == PARTITION_ENTRY_UNUSED)
					{
						continue;
					}

					// exfat
					if (part_info->Mbr.PartitionType == PARTITION_IFS)
					{
						// NOTE:
						// 这里将实现挂载磁盘中某个分区
						// 将分区的开始偏移值StartingOffset赋值给device_extension->file_offset
						// 在之后的进行ZwReadFile时，将偏移量与file_offset的值相加，得到相对于磁盘头开始的新的偏移值
						// 从新的偏移值处开始读取数据，实现对目标分区的数据读写
						device_extension->file_offset.QuadPart = part_info->StartingOffset.QuadPart;
						device_extension->file_size.QuadPart = part_info->PartitionLength.QuadPart;
						DeviceObject->AlignmentRequirement = disk_geometry.Geometry.BytesPerSector;
						break;
					}
					else
					{
						// (同上)
						device_extension->file_offset.QuadPart = part_info->StartingOffset.QuadPart;
						device_extension->file_size.QuadPart = part_info->PartitionLength.QuadPart;
						DeviceObject->AlignmentRequirement = disk_geometry.Geometry.BytesPerSector;
						break;
					}
				}
				else
				{
					// TODO:
				}
			}
		}
		ExFreePool(buffer);
	}
	else
	{
/*
	    status = ZwQueryInformationFile(
	        device_extension->file_handle,
	        &Irp->IoStatus,
	        &file_basic,
	        sizeof(FILE_BASIC_INFORMATION),
	        FileBasicInformation
	        );

	    if (!NT_SUCCESS(status))
	    {
			KdPrint(("ZwQueryInformationFile base filed, %#x \n", status));
	        ExFreePool(device_extension->file_name.Buffer);
	        ZwClose(device_extension->file_handle);
	        return status;
	    }

	    //
	    // The NT cache manager can deadlock if a filesystem that is using the cache
	    // manager is used in a virtual disk that stores its file on a filesystem
	    // that is also using the cache manager, this is why we open the file with
	    // FILE_NO_INTERMEDIATE_BUFFERING above, however if the file is compressed
	    // or encrypted NT will not honor this request and cache it anyway since it
	    // need to store the decompressed/unencrypted data somewhere, therefor we put
	    // an extra check here and don't alow disk images to be compressed/encrypted.
	    //
	    if (file_basic.FileAttributes & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED))
	    {
	        ExFreePool(device_extension->file_name.Buffer);
	        ZwClose(device_extension->file_handle);
	        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
	        Irp->IoStatus.Information = 0;
	        return STATUS_ACCESS_DENIED;
	    }
*/

	    status = ZwQueryInformationFile(
	        device_extension->file_handle,
	        &Irp->IoStatus,
	        &file_standard,
	        sizeof(FILE_STANDARD_INFORMATION),
	        FileStandardInformation
	        );

	    if (!NT_SUCCESS(status))
	    {
			KdPrint(("ZwQueryInformationFile standardinformation filed, %#x \n", status));
	        ExFreePool(device_extension->file_name.Buffer);
	        ZwClose(device_extension->file_handle);
	        return status;
	    }

	    device_extension->file_size.QuadPart = file_standard.EndOfFile.QuadPart;

	    status = ZwQueryInformationFile(
	        device_extension->file_handle,
	        &Irp->IoStatus,
	        &file_alignment,
	        sizeof(FILE_ALIGNMENT_INFORMATION),
	        FileAlignmentInformation
	        );

	    if (!NT_SUCCESS(status))
	    {
			KdPrint(("ZwQueryInformationFile file alignment filed, %#x \n", status));
	        ExFreePool(device_extension->file_name.Buffer);
	        ZwClose(device_extension->file_handle);
	        return status;
	    }

	    DeviceObject->AlignmentRequirement = file_alignment.AlignmentRequirement;

		device_extension->file_offset.QuadPart = 0;
	}

    if (device_extension->read_only)
    {
        DeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;
    }
    else
    {
        DeviceObject->Characteristics &= ~FILE_READ_ONLY_DEVICE;
    }

    device_extension->media_in_device = TRUE;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

	KdPrint(("FileDiskOpenFile <<=== \n"));

    return STATUS_SUCCESS;
}

NTSTATUS
FileDiskCloseFile (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
	KdPrint(("FileDiskCloseFile ===>> \n"));

    PDEVICE_EXTENSION device_extension;

    PAGED_CODE();

    ASSERT(DeviceObject != NULL);
    ASSERT(Irp != NULL);

    device_extension = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;

    ExFreePool(device_extension->file_name.Buffer);

    ZwClose(device_extension->file_handle);

    device_extension->media_in_device = FALSE;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

	KdPrint(("FileDiskCloseFile <<=== \n"));

    return STATUS_SUCCESS;
}

#define POOL_TAG                         'iDmI'

NTSTATUS
CreateDriveLetter(IN WCHAR DriveLetter, IN ULONG DeviceNumber)
{
  WCHAR sym_link_global_wchar[] = L"\\DosDevices\\Global\\ :";
#ifndef _WIN64
  WCHAR sym_link_wchar[] = L"\\DosDevices\\ :";
#endif
  UNICODE_STRING sym_link;
  PWCHAR device_name_buffer;
  UNICODE_STRING device_name;
  NTSTATUS status;

  // Buffer for device name
  device_name_buffer = ExAllocatePoolWithTag(PagedPool,
					     MAXIMUM_FILENAME_LENGTH *
					     sizeof(*device_name_buffer),
					     POOL_TAG);

  if (device_name_buffer == NULL)
    {
      KdPrint(("ImDisk: Insufficient pool memory.\n"));
      return STATUS_INSUFFICIENT_RESOURCES;
    }

  _snwprintf(device_name_buffer, MAXIMUM_FILENAME_LENGTH - 1,
	     DEVICE_NAME_PREFIX L"%u",
	     DeviceNumber);
  device_name_buffer[MAXIMUM_FILENAME_LENGTH - 1] = 0;
  RtlInitUnicodeString(&device_name, device_name_buffer);

#ifndef _WIN64
  sym_link_wchar[12] = DriveLetter;

  KdPrint(("ImDisk: Creating symlink '%ws' -> '%ws'.\n",
	   sym_link_wchar, device_name_buffer));

  RtlInitUnicodeString(&sym_link, sym_link_wchar);
  status = IoCreateUnprotectedSymbolicLink(&sym_link, &device_name);

  if (!NT_SUCCESS(status))
    {
      KdPrint(("ImDisk: Cannot symlink '%ws' to '%ws'. (%#x)\n",
	       sym_link_global_wchar, device_name_buffer, status));
    }
#endif

  sym_link_global_wchar[19] = DriveLetter;

  KdPrint(("ImDisk: Creating symlink '%ws' -> '%ws'.\n",
	   sym_link_global_wchar, device_name_buffer));

  RtlInitUnicodeString(&sym_link, sym_link_global_wchar);
  status = IoCreateUnprotectedSymbolicLink(&sym_link, &device_name);

  if (!NT_SUCCESS(status))
    {
      KdPrint(("ImDisk: Cannot symlink '%ws' to '%ws'. (%#x)\n",
	       sym_link_global_wchar, device_name_buffer, status));
    }

  ExFreePoolWithTag(device_name_buffer, POOL_TAG);

  return status;
}

NTSTATUS
RemoveDriveLetter(IN WCHAR DriveLetter)
{
  NTSTATUS status;
  WCHAR sym_link_global_wchar[] = L"\\DosDevices\\Global\\ :";

#ifndef _WIN64
  WCHAR sym_link_wchar[] = L"\\DosDevices\\ :";
#endif

  UNICODE_STRING sym_link;

  sym_link_global_wchar[19] = DriveLetter;

  KdPrint(("ImDisk: Removing symlink '%ws'.\n", sym_link_global_wchar));

  RtlInitUnicodeString(&sym_link, sym_link_global_wchar);
  status = IoDeleteSymbolicLink(&sym_link);

  if (!NT_SUCCESS(status))
    {
      KdPrint
	(("ImDisk: Cannot remove symlink '%ws'. (%#x)\n",
	  sym_link_global_wchar, status));
    }

#ifndef _WIN64
  sym_link_wchar[12] = DriveLetter;

  KdPrint(("ImDisk: Removing symlink '%ws'.\n", sym_link_wchar));

  RtlInitUnicodeString(&sym_link, sym_link_wchar);
  status = IoDeleteSymbolicLink(&sym_link);

  if (!NT_SUCCESS(status))
    KdPrint(("ImDisk: Cannot remove symlink '%ws'. (%#x)\n",
	     sym_link_wchar, status));
#endif

  return status;
}
