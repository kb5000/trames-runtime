// SPDX-License-Identifier: GPL-3.0-or-later
// Preserve the host's configured DNS servers and real RR data. Address lookups
// continue to use getaddrinfo, including /etc/hosts and platform name services.
#include <resolv.h>

int trames_dns_send(const unsigned char *query, int query_len,
                    unsigned char *reply, int reply_len) {
#if defined(__APPLE__) || defined(__GLIBC__)
    struct __res_state state = {0};
    if (res_ninit(&state) != 0) return -1;
    state.retrans = 1;
    state.retry = 1;
    int size = res_nsend(&state, query, query_len, reply, reply_len);
#ifdef __APPLE__
    res_ndestroy(&state);
#else
    res_nclose(&state);
#endif
    return size;
#else
    // musl's res_send reads configuration per call and keeps no global mutable
    // resolver context. It is safe to use from the existing two DNS workers.
    return res_send(query, query_len, reply, reply_len);
#endif
}
