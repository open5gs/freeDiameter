#include "fdcore-internal.h"
#include "sctp-internal.h"

#include <netinet/sctp.h>

int sctp_sockopt_event_subscribe_size = 0;
int sctp_sockopt_paddrparams_size = 0;

/* is any of the bytes from offset .. u8_size in 'u8' non-zero? return offset
 * or -1 if all zero */
static int byte_nonzero(
        const uint8_t *u8, unsigned int offset, unsigned int u8_size)
{
    int j;

    for (j = offset; j < u8_size; j++) {
        if (u8[j] != 0)
            return j;
    }

    return -1;
}

int determine_sctp_sockopt_event_subscribe_size(void)
{
    uint8_t buf[256];
    socklen_t buf_len = sizeof(buf);
    int sd, rc;

    /* only do this once */
    if (sctp_sockopt_event_subscribe_size != 0)
        return 0;

    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (sd < 0)
        return sd;

    memset(buf, 0, sizeof(buf));
    rc = getsockopt(sd, IPPROTO_SCTP, SCTP_EVENTS, buf, &buf_len);
    close(sd);
    if (rc < 0) {
        LOG_E("getsockopt(SCTP_PEER_ADDR_PARAMS) failed [%d:%s]",
                rc, strerror(errno));
        return rc;
    }

    sctp_sockopt_event_subscribe_size = buf_len;

    LOG_D("sizes of 'struct sctp_event_subscribe': "
            "compile-time %zu, kernel: %u",
            sizeof(struct sctp_event_subscribe),
            sctp_sockopt_event_subscribe_size);
    return 0;
}

/*
 * The workaround is stolen from libosmo-netif.
 * - http://osmocom.org/projects/libosmo-netif/repository/revisions/master/entry/src/stream.c
 *
 * Attempt to work around Linux kernel ABI breakage
 *
 * The Linux kernel ABI for the SCTP_EVENTS socket option has been broken
 * repeatedly.
 *  - until commit 35ea82d611da59f8bea44a37996b3b11bb1d3fd7 ( kernel < 4.11),
 *    the size is 10 bytes
 *  - in 4.11 it is 11 bytes
 *  - in 4.12 .. 5.4 it is 13 bytes
 *  - in kernels >= 5.5 it is 14 bytes
 *
 * This wouldn't be a problem if the kernel didn't have a "stupid" assumption
 * that the structure size passed by userspace will match 1:1 the length
 * of the structure at kernel compile time. In an ideal world, it would just
 * use the known first bytes and assume the remainder is all zero.
 * But as it doesn't do that, let's try to work around this */
int sctp_setsockopt_event_subscribe_workaround(
        int fd, const struct sctp_event_subscribe *event_subscribe)
{
    const unsigned int compiletime_size = sizeof(*event_subscribe);
    int rc;

    if (determine_sctp_sockopt_event_subscribe_size() < 0) {
        LOG_E("Cannot determine SCTP_EVENTS socket option size");
        return -1;
    }

    if (compiletime_size == sctp_sockopt_event_subscribe_size) {
        /* no kernel workaround needed */
        return setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS,
                event_subscribe, compiletime_size);
    } else if (compiletime_size < sctp_sockopt_event_subscribe_size) {
        /* we are using an older userspace with a more modern kernel
         * and hence need to pad the data */
        uint8_t buf[256];
        ASSERT(sctp_sockopt_event_subscribe_size <= sizeof(buf));

        memcpy(buf, event_subscribe, compiletime_size);
        memset(buf + sizeof(*event_subscribe),
                0, sctp_sockopt_event_subscribe_size - compiletime_size);
        return setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS,
                buf, sctp_sockopt_event_subscribe_size);
    } else /* if (compiletime_size > sctp_sockopt_event_subscribe_size) */ {
        /* we are using a newer userspace with an older kernel and hence
         * need to truncate the data - but only if the caller didn't try
         * to enable any of the events of the truncated portion */
        rc = byte_nonzero((const uint8_t *)event_subscribe,
                sctp_sockopt_event_subscribe_size, compiletime_size);
        if (rc >= 0) {
            LOG_E("Kernel only supports sctp_event_subscribe of %u bytes, "
                "but caller tried to enable more modern event at offset %u",
                sctp_sockopt_event_subscribe_size, rc);
            return -1;
        }

        return setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, event_subscribe,
                sctp_sockopt_event_subscribe_size);
    }
}

int determine_sctp_sockopt_paddrparams_size(void)
{
    uint8_t buf[256];
    socklen_t buf_len = sizeof(buf);
    int sd, rc;

    /* only do this once */
    if (sctp_sockopt_paddrparams_size != 0)
        return 0;

    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (sd < 0)
        return sd;

    memset(buf, 0, sizeof(buf));
    rc = getsockopt(sd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, buf, &buf_len);
    close(sd);
    if (rc < 0) {
        LOG_E("getsockopt(SCTP_PEER_ADDR_PARAMS) failed [%d:%s]",
                rc, strerror(errno));
        return rc;
    }

    sctp_sockopt_paddrparams_size = buf_len;

    LOG_D("sizes of 'struct sctp_event_subscribe': "
            "compile-time %zu, kernel: %u",
            sizeof(struct sctp_event_subscribe),
            sctp_sockopt_event_subscribe_size);
    return 0;
}

int sctp_setsockopt_paddrparams_workaround(
        int fd, const struct sctp_paddrparams *paddrparams)
{
    const unsigned int compiletime_size = sizeof(*paddrparams);
    int rc;

    if (determine_sctp_sockopt_paddrparams_size() < 0) {
        LOG_E("Cannot determine SCTP_EVENTS socket option size");
        return -1;
    }

    if (compiletime_size == sctp_sockopt_paddrparams_size) {
        /* no kernel workaround needed */
        return setsockopt(fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
                paddrparams, compiletime_size);
    } else if (compiletime_size < sctp_sockopt_paddrparams_size) {
        /* we are using an older userspace with a more modern kernel
         * and hence need to pad the data */
        uint8_t buf[256];
        ASSERT(sctp_sockopt_paddrparams_size <= sizeof(buf));

        memcpy(buf, paddrparams, compiletime_size);
        memset(buf + sizeof(*paddrparams),
                0, sctp_sockopt_paddrparams_size - compiletime_size);
        return setsockopt(fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
                buf, sctp_sockopt_paddrparams_size);
    } else /* if (compiletime_size > sctp_sockopt_paddrparams_size) */ {
        /* we are using a newer userspace with an older kernel and hence
         * need to truncate the data - but only if the caller didn't try
         * to enable any of the events of the truncated portion */
        rc = byte_nonzero((const uint8_t *)paddrparams,
                sctp_sockopt_paddrparams_size, compiletime_size);
        if (rc >= 0) {
            LOG_E("Kernel only supports sctp_event_subscribe of %u bytes, "
                "but caller tried to enable more modern event at offset %u",
                sctp_sockopt_paddrparams_size, rc);
            return -1;
        }

        return setsockopt(fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, paddrparams,
                sctp_sockopt_paddrparams_size);
    }
}
