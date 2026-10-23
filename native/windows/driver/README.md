# Windows WFP callout driver

The user-mode path (Windows Firewall rules through the NetSecurity cmdlets) works
today and is what `profast firewall apply` installs. This driver is the kernel
tier: it enforces the same policy inside the Windows Filtering Platform so a
probe is dropped before a socket is woken.

## What is here

| File               | Purpose                                                        |
| ------------------ | -------------------------------------------------------------- |
| `profast_wfp.c`    | callout + control device, policy table, classify function       |
| `ProFastWfp.inf`   | install manifest for the driver package                         |

## Policy contract

User mode pushes exactly one structure through `IOCTL_PF_SET_POLICY`:

```c
typedef struct _PF_UPDATE {
    BOOLEAN DenyInbound;      /* default-deny when TRUE                  */
    BOOLEAN AllowLocalSubnet; /* authorized peers on the LAN            */
    ULONG   PortCount;        /* <= PF_MAX_PORTS (64)                   */
    UINT16  Ports[PF_MAX_PORTS];
} PF_UPDATE;
```

The callout always permits DHCP (67/68/546/547) and ICMP control traffic, then
permits the current locator port and blocks everything else inbound. It never
opens a listening socket, never sends a packet, and never decides policy on its
own.

## Building

The driver is not part of the CMake build and not built by CI: kernel binaries
need the WDK, a test-signing setup and, for distribution, an EV certificate plus
Microsoft attestation signing.

```powershell
# Elevated "x64 Native Tools" prompt with the WDK installed
msbuild ProFastWfp.vcxproj /p:Configuration=Release /p:Platform=x64
```

A `vcxproj` is deliberately left out of the repository: the WDK wizard generates
one in about a minute and the GUIDs, target OS version and signing identity are
per-developer values that should not be committed.

## Testing safely

1. `bcdedit /set testsigning on`, reboot.
2. Create a self-signed cert, add it to *Trusted Root* and *Trusted Publishers*.
3. `sc create ProFastWfp type= kernel binPath= C:\path\profast_wfp.sys`
4. `sc start ProFastWfp`, then drive it from `pfbench`/`profastd`.
5. `sc stop ProFastWfp` to unload. Never test default-deny on a machine you
   cannot reach physically or through an out-of-band console.

## Review checklist before production

- Verify the classify path cannot block on a lock held by an unload.
- Confirm `PfSetPolicy` rejects `PortCount > PF_MAX_PORTS` (it does) and that the
  IOCTL buffer is copied before validation completes.
- Ensure the device object ACL only admits administrators and the daemon's SID;
  the skeleton relies on the default WDM ACL and must be tightened.
- Check that the callout handles IP fragments (the skeleton inspects only the
  first fragment; a full implementation must look at the fragment header).
