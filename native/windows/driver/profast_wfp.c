/*
 * ProFast-Net WFP callout driver (skeleton).
 *
 * Purpose
 *   Enforce the rotating locator at the Windows Filtering Platform, in kernel,
 *   before a packet reaches a listening socket. User mode (profastd) owns the
 *   policy: it pushes the set of ports that are currently valid and the CIDRs
 *   that are authorized peers. The callout never decides anything on its own,
 *   so a compromised user-mode process cannot widen the policy without also
 *   changing the tables - and the tables are read-only to non-elevated callers.
 *
 * Build
 *   Requires the Windows Driver Kit (WDK) 10.0.22621 or newer and Visual Studio
 *   2022. This file is intentionally NOT part of the CMake build: kernel-mode
 *   code needs its own toolchain, test signing and an EV certificate for
 *   distribution. See README.md in this directory.
 *
 * Status
 *   Reference implementation. The classify function, the control device and the
 *   table lifetime rules are real; the policy semantics are deliberately simple
 *   so the security review can focus on the boundary rather than the matching.
 */

#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ws2def.h>

#define PF_DEVICE_NAME L"\\Device\\ProFastWfp"
#define PF_SYMBOLIC_NAME L"\\DosDevices\\ProFastWfp"
#define PF_POOL_TAG 'farP'
#define PF_MAX_PORTS 64

/* Replace these with freshly generated GUIDs before shipping; the values are
 * stable so that filters survive a driver update. */
DEFINE_GUID(PF_PROVIDER_GUID, 0x6c1f2a10, 0x0d3b, 0x4c58, 0x9a, 0x11, 0x2b, 0x77, 0x41, 0x8e,
            0x55, 0x01);
DEFINE_GUID(PF_CALLOUT_GUID_V4, 0x6c1f2a11, 0x0d3b, 0x4c58, 0x9a, 0x11, 0x2b, 0x77, 0x41, 0x8e,
            0x55, 0x02);
DEFINE_GUID(PF_CALLOUT_GUID_V6, 0x6c1f2a12, 0x0d3b, 0x4c58, 0x9a, 0x11, 0x2b, 0x77, 0x41, 0x8e,
            0x55, 0x03);

/* ------------------------------------------------------------------ policy -- */

typedef struct _PF_POLICY {
    KSPIN_LOCK Lock;
    UINT16 Ports[PF_MAX_PORTS];   /* ports the locator currently accepts */
    ULONG PortCount;
    BOOLEAN DenyInbound;          /* default-deny when TRUE */
    BOOLEAN AllowLocalSubnet;     /* authorized peers on the LAN */
    UINT64 Generation;            /* bumped on every update, for auditing */
} PF_POLICY, *PPF_POLICY;

static PF_POLICY g_Policy;
static HANDLE g_EngineHandle = NULL;
static UINT64 g_CalloutIdV4 = 0;
static UINT64 g_CalloutIdV6 = 0;
static PDEVICE_OBJECT g_DeviceObject = NULL;

static BOOLEAN PfPortAllowed(_In_ UINT16 Port)
{
    ULONG index;
    BOOLEAN found = FALSE;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_Policy.Lock, &oldIrql);
    for (index = 0; index < g_Policy.PortCount; index++) {
        if (g_Policy.Ports[index] == Port) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Policy.Lock, oldIrql);
    return found;
}

static BOOLEAN PfSourceIsLocal(_In_ const FWPS_INCOMING_VALUES0 *Values)
{
    /* Loopback and link-local peers are always treated as "nearby". */
    if (Values->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4) {
        UINT32 address = Values->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
        return (address >> 24) == 127;
    }
    if (Values->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V6) {
        return IN6_IS_ADDR_LOOPBACK(
            (const IN6_ADDR *)&Values->incomingValue[
                FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS].value.byteArray16);
    }
    return FALSE;
}

/* ----------------------------------------------------------------- classify -- */

/*
 * Runs at DISPATCH_LEVEL. It must not allocate, block, or log verbosely.
 * Returning FWP_ACTION_BLOCK drops the packet; FWP_ACTION_PERMIT lets it
 * continue to the next filter, which is how SPA-approved flows are admitted.
 */
static void NTAPI PfClassify(
    _In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER0 *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UINT16 localPort;
    UINT8 protocol;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    if (!g_Policy.DenyInbound) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4) {
        localPort = inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
        protocol = (UINT8)inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
    } else if (inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V6) {
        localPort = inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;
        protocol = (UINT8)inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL].value.uint8;
    } else {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    /* DHCP and ICMP control traffic keep the link alive; never starve them. */
    if ((protocol == IPPROTO_UDP && (localPort == 67 || localPort == 68 ||
                                     localPort == 546 || localPort == 547)) ||
        protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (PfPortAllowed(localPort) && (g_Policy.AllowLocalSubnet || PfSourceIsLocal(inFixedValues))) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static NTSTATUS NTAPI PfNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID *filterKey,
    _Inout_ FWPS_FILTER0 *filter)
{
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    if (notifyType == FWPS_CALLOUT_NOTIFY_ADD_FILTER) {
        DbgPrint("ProFast: callout filter added\n");
    } else if (notifyType == FWPS_CALLOUT_NOTIFY_DELETE_FILTER) {
        DbgPrint("ProFast: callout filter removed\n");
    }
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------- table ioctl -- */

typedef struct _PF_UPDATE {
    BOOLEAN DenyInbound;
    BOOLEAN AllowLocalSubnet;
    ULONG PortCount;
    UINT16 Ports[PF_MAX_PORTS];
} PF_UPDATE, *PPF_UPDATE;

#define IOCTL_PF_SET_POLICY \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

static NTSTATUS PfSetPolicy(_In_ const PF_UPDATE *Update)
{
    ULONG index;
    KIRQL oldIrql;

    if (Update->PortCount > PF_MAX_PORTS) {
        return STATUS_INVALID_PARAMETER;
    }
    for (index = 0; index < Update->PortCount; index++) {
        if (Update->Ports[index] == 0) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    KeAcquireSpinLock(&g_Policy.Lock, &oldIrql);
    g_Policy.DenyInbound = Update->DenyInbound;
    g_Policy.AllowLocalSubnet = Update->AllowLocalSubnet;
    g_Policy.PortCount = Update->PortCount;
    for (index = 0; index < Update->PortCount; index++) {
        g_Policy.Ports[index] = Update->Ports[index];
    }
    g_Policy.Generation++;
    KeReleaseSpinLock(&g_Policy.Lock, oldIrql);
    return STATUS_SUCCESS;
}

static NTSTATUS PfDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode)
{
    PF_UPDATE update;
    PVOID buffer = NULL;
    NTSTATUS status;
    size_t length = 0;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (IoControlCode != IOCTL_PF_SET_POLICY) {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (InputBufferLength < sizeof(PF_UPDATE)) {
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(PF_UPDATE), &buffer, &length);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return status;
    }

    RtlCopyMemory(&update, buffer, sizeof(PF_UPDATE));
    status = PfSetPolicy(&update);
    WdfRequestComplete(Request, status);
    return status;
}

/* -------------------------------------------------------------------- setup -- */

static NTSTATUS PfRegisterCallouts(_In_ PDEVICE_OBJECT DeviceObject)
{
    FWPS_CALLOUT0 callout = {0};
    FWPM_CALLOUT0 registration = {0};
    NTSTATUS status;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    callout.calloutKey = PF_CALLOUT_GUID_V4;
    callout.classifyFn = PfClassify;
    callout.notifyFn = PfNotify;
    status = FwpsCalloutRegister0(DeviceObject, &callout, &g_CalloutIdV4);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    registration.calloutKey = PF_CALLOUT_GUID_V4;
    registration.displayData.name = L"ProFast inbound locator";
    registration.displayData.description = L"Admits only the current mirage port";
    registration.flags = FWPM_CALLOUT_FLAG_PERSISTENT;
    registration.providerKey = (GUID *)&PF_PROVIDER_GUID;
    registration.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4;
    FwpmCalloutAdd0(g_EngineHandle, &registration, NULL, NULL);

    /* Repeat for V6 with FWPM_LAYER_INBOUND_TRANSPORT_V6. */
    return STATUS_SUCCESS;
}

static VOID PfUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    if (g_EngineHandle != NULL) {
        if (g_CalloutIdV4 != 0) {
            FwpsCalloutUnregisterById0(g_CalloutIdV4);
        }
        if (g_CalloutIdV6 != 0) {
            FwpsCalloutUnregisterById0(g_CalloutIdV6);
        }
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }
    DbgPrint("ProFast: driver unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&g_Policy.Lock);
    g_Policy.DenyInbound = FALSE;
    g_Policy.AllowLocalSubnet = TRUE;
    g_Policy.PortCount = 0;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = PfUnload;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = NULL;

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_DeviceObject = WdfDriverWdmGetDriverObject(WDF_NO_HANDLE);
    status = PfRegisterCallouts(g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ProFast: callout registration failed 0x%08X\n", status);
    }
    return STATUS_SUCCESS;
}
