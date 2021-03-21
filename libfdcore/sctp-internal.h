#ifndef _SCTP_INTERNAL_H
#define _SCTP_INTERNAL_H

extern int sctp_sockopt_event_subscribe_size;
extern int sctp_sockopt_paddrparams_size;

struct sctp_event_subscribe;
struct sctp_paddrparams;

int determine_sctp_sockopt_event_subscribe_size(void);
int determine_sctp_sockopt_paddrparams_size(void);

int sctp_setsockopt_event_subscribe_workaround(
        int fd, const struct sctp_event_subscribe *event_subscribe);
int sctp_setsockopt_paddrparams_workaround(
        int fd, const struct sctp_paddrparams *paddrparams);

#endif /* _SCTP_INTERNAL_H */
