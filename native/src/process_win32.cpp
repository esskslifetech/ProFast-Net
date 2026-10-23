#include "profast/native.h"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>

namespace {

int status_from_win32(DWORD err) {
    switch (err) {
    case ERROR_SUCCESS:
        return PF_OK;
    case ERROR_INVALID_PARAMETER:
        return PF_EINVAL;
    case ERROR_ACCESS_DENIED:
        return PF_EPERM;
    case ERROR_NOT_SUPPORTED:
    case ERROR_CALL_NOT_IMPLEMENTED:
        return PF_ENOTSUP;
    default:
        return PF_EIO;
    }
}

DWORD priority_class_for_level(int level, bool *ok) {
    *ok = true;
    switch (level) {
    case -2:
        return IDLE_PRIORITY_CLASS;
    case -1:
        return BELOW_NORMAL_PRIORITY_CLASS;
    case 0:
        return NORMAL_PRIORITY_CLASS;
    case 1:
        return ABOVE_NORMAL_PRIORITY_CLASS;
    case 2:
        return HIGH_PRIORITY_CLASS;
    default:
        *ok = false;
        return NORMAL_PRIORITY_CLASS;
    }
}

} // namespace

extern "C" {

int pf_set_process_priority(uint32_t pid, int level) {
    bool ok = false;
    const DWORD cls = priority_class_for_level(level, &ok);
    if (!ok) {
        return PF_EINVAL;
    }

    HANDLE h = OpenProcess(PROCESS_SET_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h) {
        return status_from_win32(GetLastError());
    }
    const BOOL rc = SetPriorityClass(h, cls);
    const DWORD err = rc ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    return status_from_win32(err);
}

/*
 * Windows 11 applies "EcoQoS" throttling to background apps, which quietly
 * halves the CPU of the process the user is actively watching. Turning power
 * throttling off for the focused process is what actually restores throughput.
 */
int pf_disable_power_throttling(uint32_t pid, int disable) {
    HANDLE h = OpenProcess(PROCESS_SET_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h) {
        return status_from_win32(GetLastError());
    }

    PROCESS_POWER_THROTTLING_STATE state;
    ZeroMemory(&state, sizeof(state));
    state.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    state.ControlMask =
        disable ? PROCESS_POWER_THROTTLING_EXECUTION_SPEED : PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    state.StateMask = disable ? 0 : PROCESS_POWER_THROTTLING_EXECUTION_SPEED;

    const BOOL rc = SetProcessInformation(h, ProcessPowerThrottling, &state, sizeof(state));
    const DWORD err = rc ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);

    if (!rc && err == ERROR_INVALID_PARAMETER) {
        return PF_ENOTSUP; /* pre-Windows 10 1709 */
    }
    return status_from_win32(err);
}

int pf_set_socket_dscp(intptr_t sock, uint8_t dscp, int ipv6) {
    (void)sock;
    (void)dscp;
    (void)ipv6;
    /* Per-socket DSCP requires the QoS2 API and an elevated policy. The daemon
       installs New-NetQosPolicy rules instead; see internal/qos. */
    return PF_ENOTSUP;
}

} // extern "C"

#endif /* _WIN32 */
