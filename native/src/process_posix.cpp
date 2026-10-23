#include "profast/native.h"

#include <cerrno>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>

namespace {

int nice_for_level(int level) {
    switch (level) {
    case -2:
        return 15;
    case -1:
        return 5;
    case 0:
        return 0;
    case 1:
        return -5;
    case 2:
        return -10;
    default:
        return 99;
    }
}

int status_from_errno(int err) {
    switch (err) {
    case 0:
        return PF_OK;
    case EINVAL:
        return PF_EINVAL;
    case EACCES:
    case EPERM:
        return PF_EPERM;
    case ENOTSUP:
#if defined(EOPNOTSUPP) && (EOPNOTSUPP != ENOTSUP)
    case EOPNOTSUPP:
#endif
        return PF_ENOTSUP;
    default:
        return PF_EIO;
    }
}

} // namespace

extern "C" {

int pf_set_process_priority(uint32_t pid, int level) {
    const int nice_value = nice_for_level(level);
    if (nice_value == 99) {
        return PF_EINVAL;
    }
    if (setpriority(PRIO_PROCESS, static_cast<id_t>(pid), nice_value) != 0) {
        return status_from_errno(errno);
    }
    return PF_OK;
}

int pf_disable_power_throttling(uint32_t pid, int disable) {
    (void)pid;
    (void)disable;
    /* POSIX schedulers expose this through cgroups / taskpolicy, handled by the
       control plane, not by a portable libc call. */
    return PF_ENOTSUP;
}

int pf_set_socket_dscp(intptr_t sock, uint8_t dscp, int ipv6) {
    if (sock == 0 || dscp > 63) {
        return PF_EINVAL;
    }
    const int tos = static_cast<int>(dscp) << 2;
    const int rc = ipv6 ? setsockopt(static_cast<int>(sock), IPPROTO_IPV6, IPV6_TCLASS, &tos,
                                     sizeof(tos))
                        : setsockopt(static_cast<int>(sock), IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    if (rc != 0) {
        return status_from_errno(errno);
    }
    return PF_OK;
}

} // extern "C"
