/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined(__FreeBSD__) && !defined(__Userspace__)
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#endif

#ifndef _NETINET_SCTP_PLPMTUD_H_
#define _NETINET_SCTP_PLPMTUD_H_

#if defined(_KERNEL) || defined(__Userspace__)

#define SCTP_PLPMTUD_STATE_DISABLED 0
#define SCTP_PLPMTUD_STATE_BASE 1
#define SCTP_PLPMTUD_STATE_ERROR 2
#define SCTP_PLPMTUD_STATE_SEARCH 3
#define SCTP_PLPMTUD_STATE_SEARCHCOMPLETE 4

#define SCTP_PLPMTUD_STEPSIZE 4
#define SCTP_PLPMTUD_BASE_IPV4 1200
#define SCTP_PLPMTUD_BASE_IPV6 1280
#define SCTP_PLPMTUD_MAX_IP_SIZE 65535
#define SCTP_PLPMTUD_ALGORITHM_UP 1
#define SCTP_PLPMTUD_ALGORITHM_OPTBINARY 2

/*
 * Function prototypes
 */
void sctp_plpmtud_init(struct sctp_tcb *, struct sctp_nets *);
void sctp_plpmtud_start(struct sctp_tcb *, struct sctp_nets *);
void sctp_plpmtud_delayed_start(struct sctp_tcb *, struct sctp_nets *);
void sctp_plpmtud_on_probe_acked(struct sctp_tcb *, struct sctp_nets *, uint32_t);
void sctp_plpmtud_on_probe_timeout(struct sctp_tcb *, struct sctp_nets *);
void sctp_plpmtud_on_ptb_received(struct sctp_tcb *, struct sctp_nets *, uint32_t);
void sctp_plpmtud_on_pmtu_invalid(struct sctp_tcb *, struct sctp_nets *, uint32_t);
void sctp_plpmtud_end(struct sctp_tcb *stcb, struct sctp_nets *net);

#endif				/* _KERNEL */
#endif
