#include "profast/native.h"

extern "C" {

const char *pf_version(void) { return "0.1.0"; }

const char *pf_strerror(int status) {
    switch (status) {
    case PF_OK:
        return "ok";
    case PF_EINVAL:
        return "invalid argument";
    case PF_ENOTSUP:
        return "operation not supported on this platform";
    case PF_EPERM:
        return "permission denied (run elevated)";
    case PF_EIO:
        return "i/o error";
    case PF_EBUSY:
        return "resource busy or rate limited";
    case PF_EAUTH:
        return "authentication failed";
    case PF_EREPLAY:
        return "replayed packet rejected";
    case PF_ECLOCK:
        return "epoch outside the accepted clock window";
    default:
        return "unknown error";
    }
}

} // extern "C"
