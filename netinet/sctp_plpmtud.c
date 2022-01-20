/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2008, by Cisco Systems, Inc. All rights reserved.
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

#include <netinet/sctp_os.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_sysctl.h>
#ifdef INET6
#if defined(__Userspace__) || defined(__FreeBSD__)
#include <netinet6/sctp6_var.h>
#endif
#endif
#include <netinet/sctp_header.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctp_timer.h>
#include <netinet/sctp_indata.h>
#include <netinet/sctp_auth.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctp_bsd_addr.h>
#include <netinet/sctp_plpmtud.h>
#if defined(__Userspace__)
#include <netinet/sctp_constants.h>
#endif
#if defined(__FreeBSD__) && !defined(__Userspace__)
#include <netinet/sctp_kdtrace.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <sys/proc.h>
#endif


static void
sctp_plpmtud_newstate(struct sctp_tcb *, struct sctp_nets *, uint8_t);

static void
sctp_plpmtud_send_probe(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t size, uint8_t rapid)
{
	int clock_granularity;
	uint32_t expected_response_time;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: send probe for %u at %u\n", size, sctp_get_tick_count());
	net->plpmtud_probe_count++;
	net->plpmtud_probed_size = size;
	sctp_send_plpmtud_probe(stcb, net, size, net->plpmtud_overhead);
	/* set probe timer
	 * srtt = lastsa >> SCTP_RTT_SHIFT = lastsa >> 3 = lastsa / 8
	 * rttvar = lastsv >> SCTP_RTT_VAR_SHIFT = lastsv >> 2 = lastsv / 4
	 * --> 4*rttvar = lastsv
	 */
	clock_granularity = 2 * max(1, 1000/hz);
	expected_response_time = (net->lastsa >> SCTP_RTT_SHIFT) + max(clock_granularity, net->lastsv);
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: expected_response_time = (%d >> %d) + max(2*%d, %d) = %d + %d = %u\n", net->lastsa, SCTP_RTT_SHIFT, clock_granularity, net->lastsv, (net->lastsa >> SCTP_RTT_SHIFT), max((2*clock_granularity), net->lastsv), expected_response_time);
	if (rapid) {
		net->plpmtud_timer_value = expected_response_time;
	} else {
		net->plpmtud_timer_value = max(expected_response_time, net->plpmtud_min_probe_rtx_time);
	}
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net);
}

static void
sctp_plpmtud_set_pmtu(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t pmtu)
{
	uint32_t smallest_net_mtu, old_pmtu;
	struct sctp_nets *mnet;

	old_pmtu = net->mtu;
	net->mtu = pmtu;

	/* update smallest_mtu for the asoc */
	if (pmtu < stcb->asoc.smallest_mtu) {
		/* smallest_mtu reduced. */
		sctp_pathmtu_adjustment(stcb, pmtu, false);
	} else if (old_pmtu == stcb->asoc.smallest_mtu && pmtu > old_pmtu) {
		/* smallest_mtu might have been increased */
		/* find the new smallest mtu and use it */
		smallest_net_mtu = pmtu;
		TAILQ_FOREACH(mnet, &stcb->asoc.nets, sctp_next) {
			if (smallest_net_mtu < mnet->mtu) {
				smallest_net_mtu = mnet->mtu;
			}
		}
		stcb->asoc.smallest_mtu = smallest_net_mtu;
	}
}

static void
sctp_plpmtud_cache_pmtu(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t pmtu, uint8_t increase)
{
	if (net->ro._s_addr != NULL) {
#if defined(__FreeBSD__) && !defined(__Userspace__)
		if (pmtu < sctp_hc_get_mtu(&net->ro._l_addr, stcb->sctp_ep->fibnum) || increase) {
			sctp_hc_set_mtu(&net->ro._l_addr, stcb->sctp_ep->fibnum, pmtu);
		}
		if (pmtu < SCTP_GATHER_MTU_FROM_ROUTE(net->ro._s_addr, &net->ro._l_addr.sa, net->ro.ro_nh) || increase) {
			SCTP_SET_MTU_OF_ROUTE(&net->ro._l_addr.sa, net->ro.ro_nh, pmtu);
		}
#else
		if (pmtu < SCTP_GATHER_MTU_FROM_ROUTE(net->ro._s_addr, &net->ro._l_addr.sa, net->ro.ro_rt) || increase) {
			SCTP_SET_MTU_OF_ROUTE(&net->ro._l_addr.sa, net->ro.ro_rt, pmtu);
		}
#endif
	}
}

static void
sctp_plpmtud_disabled_start(struct sctp_tcb *stcb, struct sctp_nets *net) {
	uint32_t rmtu, hcmtu;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: DISABLED start\n");
	/* use MTU from route or from host cache as temporarily max_mtu */
	rmtu = hcmtu = 0;
	if (net->ro._s_addr != NULL) {
#if defined(__FreeBSD__) && !defined(__Userspace__)
		rmtu = SCTP_GATHER_MTU_FROM_ROUTE(net->ro._s_addr, &net->ro._l_addr.sa, net->ro.ro_nh);
		hcmtu = sctp_hc_get_mtu(&net->ro._l_addr, stcb->sctp_ep->fibnum);
#else
		rmtu = SCTP_GATHER_MTU_FROM_ROUTE(net->ro._s_addr, &net->ro._l_addr.sa, net->ro.ro_rt);
#endif
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: found rmtu=%u, hcmtu=%u\n", rmtu, hcmtu);

		if (0 < rmtu && rmtu < net->plpmtud_max_pmtu) {
			net->plpmtud_max_pmtu = (rmtu >> 2) << 2;
		}
		if (0 < hcmtu & hcmtu < net->plpmtud_max_pmtu) {
			net->plpmtud_max_pmtu = (hcmtu >> 2) << 2;
		}
		if (net->plpmtud_min_pmtu > net->plpmtud_max_pmtu) {
			net->plpmtud_min_pmtu = net->plpmtud_max_pmtu;
		}
	}

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: start with min_pmtu=%u, max_pmtu=%u, initial_min_pmtu=%u, initial_max_pmtu=%u, overhead=%u\n", net->plpmtud_min_pmtu, net->plpmtud_max_pmtu, net->plpmtud_initial_min_pmtu, net->plpmtud_initial_max_pmtu, net->plpmtud_overhead);
	sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_BASE);
}

static void
sctp_plpmtud_disabled_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t expired_probe_size)
{
	sctp_plpmtud_disabled_start(stcb, net);
}

static void
sctp_plpmtud_base_start(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE start\n");
	net->plpmtud_min_pmtu = net->plpmtud_initial_min_pmtu;
	sctp_plpmtud_set_pmtu(stcb, net, max(net->plpmtud_min_pmtu, net->plpmtud_base_pmtu));
	net->plpmtud_probe_count = 0;
	sctp_plpmtud_send_probe(stcb, net, max(net->plpmtud_min_pmtu, net->plpmtud_base_pmtu), 0);
}

static void
sctp_plpmtud_base_on_probe_acked(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t acked_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE %u acked\n", acked_probe_size);
	if (acked_probe_size < net->plpmtud_base_pmtu) {
		/* ignore ack */
		return;
	}
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_1);
	if (acked_probe_size < net->plpmtud_max_pmtu) {
		net->plpmtud_min_pmtu = acked_probe_size;
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCH);
	} else {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCHCOMPLETE);
	}
}

static void
sctp_plpmtud_base_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t expired_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE %u expired\n", expired_probe_size);
	if (net->plpmtud_probe_count < net->plpmtud_max_probes) {
		sctp_plpmtud_send_probe(stcb, net, expired_probe_size, 0);
	} else {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_ERROR);
	}
}

static void
sctp_plpmtud_base_on_ptb_received(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t ptb_mtu)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE PTB received reporting an MTU of %u\n", ptb_mtu);
	if (net->plpmtud_min_pmtu <= ptb_mtu && ptb_mtu < net->plpmtud_base_pmtu) {
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_2);
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_ERROR);
	}
}

static void
sctp_plpmtud_error_start(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR start\n");
	net->plpmtud_min_pmtu = net->plpmtud_initial_min_pmtu;
	sctp_plpmtud_set_pmtu(stcb, net, net->plpmtud_min_pmtu);
	if (net->plpmtud_probed_size > net->plpmtud_min_pmtu) {
		net->plpmtud_probe_count = 0;
		sctp_plpmtud_send_probe(stcb, net, net->plpmtud_min_pmtu, 0);
	} else {
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR min pmtu %u was already probed without success, stop.\n", net->plpmtud_min_pmtu);
	}
}

static void
sctp_plpmtud_error_on_probe_acked(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t acked_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR %u acked\n", acked_probe_size);
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_3);
	sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCH);
}

static void
sctp_plpmtud_error_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t expired_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR %u expired\n", expired_probe_size);
	if (net->plpmtud_probe_count < net->plpmtud_max_probes) {
		sctp_plpmtud_send_probe(stcb, net, net->plpmtud_min_pmtu, 0);
	} else {
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR probe for min pmtu %u failed, stop.\n", net->plpmtud_min_pmtu);
	}
}

static void
sctp_plpmtud_search_add_probe(struct sctp_plpmtud_probe_head *head, uint32_t size)
{
	uint16_t count = 1;
	struct sctp_plpmtud_probe *probe, *temp;
	TAILQ_FOREACH_SAFE(probe, head, next, temp) {
		if (probe->size == size) {
			count = probe->count + 1;
			TAILQ_REMOVE(head, probe, next);
			SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_net), probe);
		}
	}

	probe = SCTP_ZONE_GET(SCTP_BASE_INFO(ipi_zone_net), struct sctp_plpmtud_probe);
	probe->size = size;
	probe->count = count;
	TAILQ_INSERT_TAIL(head, probe, next);
}

static struct sctp_plpmtud_probe *
sctp_plpmtud_search_get_probe(struct sctp_plpmtud_probe_head *head, uint32_t size)
{
	struct sctp_plpmtud_probe *probe;
	TAILQ_FOREACH(probe, head, next) {
		if (probe->size == size) {
			return probe;
		}
	}
	return NULL;
}

static void
sctp_plpmtud_search_remove_probes(struct sctp_plpmtud_probe_head *head, uint32_t size, uint8_t smaller, uint8_t equal, uint8_t larger)
{
	struct sctp_plpmtud_probe *probe, *temp;
	TAILQ_FOREACH_SAFE(probe, head, next, temp) {
		if ((equal && probe->size == size)
		 || (larger && probe->size > size)
		 || (smaller && probe->size < size)) {

			TAILQ_REMOVE(head, probe, next);
			SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_net), probe);
		}
	}
}

static struct sctp_plpmtud_probe *
sctp_plpmtud_search_get_smallest_probe(struct sctp_plpmtud_probe_head *head)
{
	struct sctp_plpmtud_probe *probe;
	struct sctp_plpmtud_probe *smallest = TAILQ_FIRST(head);

	TAILQ_FOREACH(probe, head, next) {
		if (probe->size < smallest->size) {
			smallest = probe;
		}
	}
	return smallest;
}

static uint8_t
sctp_plpmtud_search_exists_larger_probe(struct sctp_plpmtud_probe_head *head, uint32_t size)
{
	struct sctp_plpmtud_probe *probe;
	TAILQ_FOREACH(probe, head, next) {
		if (probe->size > size) {
			return 1;
		}
	}
	return 0;
}

static uint32_t
sctp_plpmtud_search_up_get_next_candidate(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	uint32_t next = net->mtu + SCTP_PLPMTUD_STEPSIZE;
	if (next >= net->plpmtud_smallest_failed
	 || next > net->plpmtud_smallest_expired
	 || next > net->plpmtud_max_pmtu) {
		return 0;
	}
	return next;
}

static uint32_t
sctp_plpmtud_search_optbinary_get_next_candidate(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	if (net->mtu == net->plpmtud_min_pmtu && net->plpmtud_smallest_expired == SCTP_PLPMTUD_MAX_IP_SIZE) {
		/* start optimistic */
		return net->plpmtud_max_pmtu;
	}
	uint32_t min = net->mtu;
	uint32_t max = net->plpmtud_max_pmtu;
	if (max > net->plpmtud_smallest_failed - SCTP_PLPMTUD_STEPSIZE) {
		max = net->plpmtud_smallest_failed - SCTP_PLPMTUD_STEPSIZE;
	}
	if (max > net->plpmtud_smallest_expired) {
		max = net->plpmtud_smallest_expired;
	}
	/* ceil(((double)(max - min)) / (SCTP_PLPMTUD_STEPSIZE * 2)) * SCTP_PLPMTUD_STEPSIZE + min; */
	uint32_t next = ((max - min + SCTP_PLPMTUD_STEPSIZE * 2 - 1) / (SCTP_PLPMTUD_STEPSIZE * 2)) * SCTP_PLPMTUD_STEPSIZE + min;
	if (next == net->mtu) {
		return 0;
	}
	return next;
}

static void
sctp_plpmtud_search_send_probe(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t size)
{
	uint8_t rapid;

	sctp_plpmtud_search_add_probe(&(net->plpmtud_probes), size);

	rapid = 0;
	if (net->plpmtud_last_probe_acked) {
		/* the last probe packet was acked, which gives us confidence in the estimated RTT */
		rapid = 1;
	} else {
		struct sctp_plpmtud_probe *smallest = sctp_plpmtud_search_get_smallest_probe(&(net->plpmtud_probes));
		if (smallest->size > net->mtu + SCTP_PLPMTUD_STEPSIZE) {
			/* we still have the possibility to probe for smaller candidates */
			rapid = 1;
		}
	}
	sctp_plpmtud_send_probe(stcb, net, size, rapid);
}

static void
sctp_plpmtud_search_start(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH start\n");
	net->plpmtud_last_probe_acked = 0;
	net->plpmtud_smallest_expired = SCTP_PLPMTUD_MAX_IP_SIZE;
	net->plpmtud_smallest_failed = SCTP_PLPMTUD_MAX_IP_SIZE;
	TAILQ_INIT(&(net->plpmtud_probes));

	switch(stcb->asoc.plpmtud_search_algorithm) {
	case SCTP_PLPMTUD_ALGORITHM_UP:
		net->plpmtud_get_next_candidate = &sctp_plpmtud_search_up_get_next_candidate;
		break;
	default:
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: No search algorithm with ID %u, use OptBinary\n", stcb->asoc.plpmtud_search_algorithm);
	case SCTP_PLPMTUD_ALGORITHM_OPTBINARY:
		net->plpmtud_get_next_candidate = &sctp_plpmtud_search_optbinary_get_next_candidate;
		break;
	}

	uint32_t first = net->plpmtud_get_next_candidate(stcb, net);
	sctp_plpmtud_search_send_probe(stcb, net, first);
}

static void
sctp_plpmtud_search_on_probe_acked(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t acked_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH %u acked at %u\n", acked_probe_size, sctp_get_tick_count());
	if (acked_probe_size < net->mtu) {
		/* ignore ack */
		return;
	}
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_4);
	net->plpmtud_last_probe_acked = 1;
	sctp_plpmtud_set_pmtu(stcb, net, acked_probe_size);
	if (net->mtu >= net->plpmtud_max_pmtu) {
		/* max PMTU acked, transistion to SEARCH_COMPLETE */
		return sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCHCOMPLETE);
	}
	sctp_plpmtud_search_remove_probes(&(net->plpmtud_probes), acked_probe_size, 1, 1, 0);
	if (acked_probe_size >= net->plpmtud_smallest_expired) {
		/* update smallest expired */
		struct sctp_plpmtud_probe *smallest = sctp_plpmtud_search_get_smallest_probe(&(net->plpmtud_probes));
		if (smallest == NULL) {
			net->plpmtud_smallest_expired = SCTP_PLPMTUD_MAX_IP_SIZE;
		} else {
			net->plpmtud_smallest_expired = smallest->size;
		}
	}

	uint32_t probe_size = net->plpmtud_get_next_candidate(stcb, net);
	if (probe_size > 0) {
		sctp_plpmtud_search_send_probe(stcb, net, probe_size);
	} else {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCHCOMPLETE);
	}
}

static void
sctp_plpmtud_search_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t expired_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH %u expired at %u\n", expired_probe_size, sctp_get_tick_count());
	net->plpmtud_last_probe_acked = 0;
	net->plpmtud_smallest_expired = expired_probe_size;

	struct sctp_plpmtud_probe *probe = sctp_plpmtud_search_get_probe(&(net->plpmtud_probes), expired_probe_size);
	if (probe->count == net->plpmtud_max_probes) {
		net->plpmtud_smallest_failed = expired_probe_size;
		sctp_plpmtud_search_remove_probes(&(net->plpmtud_probes), expired_probe_size, 0, 1, 1);
	}

	/* try to send a new probe packet */
	uint32_t probe_size = net->plpmtud_get_next_candidate(stcb, net);
	if (probe_size > 0) {
		sctp_plpmtud_search_send_probe(stcb, net, probe_size);
	} else {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCHCOMPLETE);
	}
}

static void
sctp_plpmtud_search_on_ptb_received(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t ptb_mtu)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH PTB received reporting an MTU of %u\n", ptb_mtu);
	/* correct ptbMtu to the next smaller multiple of 4 */
	ptb_mtu = (ptb_mtu >> 2) << 2;
	if (ptb_mtu < net->mtu) {
		/* reported MTU is smaller than a previously successful probed size. Go back to BASE. */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_5);
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_BASE);
	} else if (ptb_mtu == net->mtu) {
		/* reported MTU confirmed current PMTU. Transition to SEARCH_COMPLETE */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_6);
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCHCOMPLETE);
	} else if (!sctp_plpmtud_search_exists_larger_probe(&(net->plpmtud_probes), ptb_mtu)) {
		/* no probe sent that would trigger this PTB, ignore. */
	} else {
		/* PMTU < PTB_MTU < MAX_PMTU */
		/* use reported MTU for a new probe */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_7);
		net->plpmtud_last_probe_acked = 0;
		net->plpmtud_max_pmtu = ptb_mtu;
		sctp_plpmtud_search_remove_probes(&(net->plpmtud_probes), ptb_mtu, 0, 0, 1);
		if (sctp_plpmtud_search_get_probe(&(net->plpmtud_probes), ptb_mtu) == NULL) {
			sctp_plpmtud_search_send_probe(stcb, net, ptb_mtu);
		}
	}
}

static void
sctp_plpmtud_search_on_pmtu_invalid(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t largest_acked_since_loss)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH PMTU reported invalid with largestAckedSinceLoss=%u\n", largest_acked_since_loss);
	/* return to BASE */
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_8);
	sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_BASE);
}

static void
sctp_plpmtud_search_end(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	/* cleanup probes list */
	sctp_plpmtud_search_remove_probes(&(net->plpmtud_probes), 0, 1, 1, 1);
}

static void
sctp_plpmtud_searchcomplete_start(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE start\n");
	net->plpmtud_min_pmtu = net->plpmtud_initial_min_pmtu;
	net->plpmtud_max_pmtu = net->plpmtud_initial_max_pmtu;

	/* write discovered PMTU into the host cache (FreeBSD) or set it for the route */
	sctp_plpmtud_cache_pmtu(stcb, net, net->mtu, true);

	if (net->mtu < net->plpmtud_max_pmtu) {
		net->plpmtud_probed_size = 0;
		net->plpmtud_timer_value = net->plpmtud_raise_time;
		sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net);
	}
}

static void
sctp_plpmtud_searchcomplete_on_probe_acked(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t acked_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE %u acked\n", acked_probe_size);
	if (acked_probe_size <= net->mtu) {
		/* ignore ack */
		return;
	}

	/* PMTU increased */
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_9);
	sctp_plpmtud_set_pmtu(stcb, net, acked_probe_size);
	if (net->mtu < net->plpmtud_max_pmtu) {
		net->plpmtud_min_pmtu = acked_probe_size;
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCH);
	}
}

static void
sctp_plpmtud_searchcomplete_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t expired_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE %u expired\n", expired_probe_size);
	if (expired_probe_size == 0) {
		/* raise timer fired */
		uint32_t next = net->mtu + SCTP_PLPMTUD_STEPSIZE;
		if (next > net->plpmtud_max_pmtu) {
			next = net->plpmtud_max_pmtu;
		}
		net->plpmtud_probe_count = 0;
		sctp_plpmtud_send_probe(stcb, net, next, 0);
	} else {
		/* raise probe expired */
		if (net->plpmtud_probe_count < net->plpmtud_max_probes) {
			sctp_plpmtud_send_probe(stcb, net, expired_probe_size, 0);
		} else {
			/* give up, reschedule raise timer */
			net->plpmtud_probed_size = 0;
			net->plpmtud_timer_value = net->plpmtud_raise_time;
			sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net);
		}
	}
}

static void
sctp_plpmtud_searchcomplete_on_ptb_received(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t ptb_mtu)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE PTB received reporting an MTU of %u\n", ptb_mtu);
	/* correct ptbMtu to the next smaller multiple of 4 */
	ptb_mtu = (ptb_mtu >> 2) << 2;
	if (ptb_mtu < net->mtu) {
		/* reported MTU is smaller than the current PMTU. Go back to BASE. */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_10);
		net->plpmtud_max_pmtu = ptb_mtu;
		sctp_plpmtud_cache_pmtu(stcb, net, ptb_mtu, false);
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_BASE);
	} else if (ptb_mtu == net->mtu) {
		/* reported MTU confirmed the current PMTU. Reschedule RAISE_TIMER */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_11);
		net->plpmtud_probed_size = 0;
		net->plpmtud_timer_value = net->plpmtud_raise_time;
		sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net);
	} /* else {
		no probe outstanding or
		reported MTU is equal or larger than the currently probed size or
		PMTU < ptbMtu < PMTU+4
		--> ignore PTB.
	} */
}

static void
sctp_plpmtud_searchcomplete_on_pmtu_invalid(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t largest_acked_since_loss)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE PMTU reported invalid with largest_acked_since_loss=%u\n", largest_acked_since_loss);
	net->plpmtud_max_pmtu = net->mtu;
	if (largest_acked_since_loss >= net->plpmtud_min_pmtu) {
		net->plpmtud_min_pmtu = largest_acked_since_loss;
		sctp_plpmtud_set_pmtu(stcb, net, largest_acked_since_loss);
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCH);
	} else {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_BASE);
	}
}

void
sctp_plpmtud_init(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	uint32_t imtu;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: init\n");

	net->plpmtud_timer_value = 0;
	net->plpmtud_probed_size = 0;
	net->plpmtud_state = SCTP_PLPMTUD_STATE_DISABLED;

	/* determine max_pmtu */
	net->plpmtud_max_pmtu = (SCTP_PLPMTUD_MAX_IP_SIZE >> 2) << 2;
	imtu = 0;
	if (net->ro._s_addr != NULL && net->ro._s_addr->ifn_p != NULL) {
		imtu = SCTP_GATHER_MTU_FROM_INTFC(net->ro._s_addr->ifn_p);
	}
	if (0 < imtu && imtu < net->plpmtud_max_pmtu) {
		net->plpmtud_max_pmtu = (imtu >> 2) << 2;
	}

	/* set min_pmtu, base_pmtu and overhead */
	switch (net->ro._l_addr.sa.sa_family) {
#ifdef INET
	case AF_INET:
		net->plpmtud_min_pmtu = (stcb->asoc.plpmtud_ipv4_min_mtu >> 2) << 2;
		net->plpmtud_base_pmtu = SCTP_PLPMTUD_BASE_IPV4;
		net->plpmtud_overhead = SCTP_MIN_V4_OVERHEAD;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		net->plpmtud_min_pmtu = (stcb->asoc.plpmtud_ipv6_min_mtu >> 2) << 2;
		net->plpmtud_base_pmtu = SCTP_PLPMTUD_BASE_IPV6;
		net->plpmtud_overhead = SCTP_MIN_OVERHEAD;
		break;
#endif
	default:
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: unknown address family, disable PLPMTUD\n");
		net->plpmtud_enabled = 0;
		return;
	}
	if (net->plpmtud_min_pmtu > net->plpmtud_max_pmtu) {
		net->plpmtud_min_pmtu = net->plpmtud_max_pmtu;
	}
	if (net->port) {
		net->plpmtud_overhead += (uint32_t)sizeof(struct udphdr);
	}

	net->plpmtud_initial_min_pmtu = net->plpmtud_min_pmtu;
	net->plpmtud_initial_max_pmtu = net->plpmtud_max_pmtu;
}

void
sctp_plpmtud_start(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_DISABLED:
		return sctp_plpmtud_disabled_start(stcb, net);
	case SCTP_PLPMTUD_STATE_BASE:
		return sctp_plpmtud_base_start(stcb, net);
	case SCTP_PLPMTUD_STATE_ERROR:
		return sctp_plpmtud_error_start(stcb, net);
	case SCTP_PLPMTUD_STATE_SEARCH:
		return sctp_plpmtud_search_start(stcb, net);
	case SCTP_PLPMTUD_STATE_SEARCHCOMPLETE:
		return sctp_plpmtud_searchcomplete_start(stcb, net);
	}
}

void
sctp_plpmtud_delayed_start(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	uint32_t delay, rndval, jitter;

	if (net->RTO == 0) {
		delay = stcb->asoc.initial_rto;
	} else {
		delay = net->RTO;
	}
	rndval = sctp_select_initial_TSN(&stcb->sctp_ep->sctp_ep);
	jitter = rndval % delay;
	if (delay > 1) {
		delay >>= 1;
	}
	if (delay < (UINT32_MAX - delay)) {
		delay += jitter;
	} else {
		delay = UINT32_MAX;
	}
	net->plpmtud_timer_value = delay;
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net);
}

void
sctp_plpmtud_on_probe_acked(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t acked_probe_size)
{
	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_BASE:
		return sctp_plpmtud_base_on_probe_acked(stcb, net, acked_probe_size);
	case SCTP_PLPMTUD_STATE_ERROR:
		return sctp_plpmtud_error_on_probe_acked(stcb, net, acked_probe_size);
	case SCTP_PLPMTUD_STATE_SEARCH:
		return sctp_plpmtud_search_on_probe_acked(stcb, net, acked_probe_size);
	case SCTP_PLPMTUD_STATE_SEARCHCOMPLETE:
		return sctp_plpmtud_searchcomplete_on_probe_acked(stcb, net, acked_probe_size);
	}
}

void
sctp_plpmtud_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	uint32_t expired_probe_size;

	expired_probe_size = net->plpmtud_probed_size;
	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_DISABLED:
		return sctp_plpmtud_disabled_on_probe_timeout(stcb, net, expired_probe_size);
	case SCTP_PLPMTUD_STATE_BASE:
		return sctp_plpmtud_base_on_probe_timeout(stcb, net, expired_probe_size);
	case SCTP_PLPMTUD_STATE_ERROR:
		return sctp_plpmtud_error_on_probe_timeout(stcb, net, expired_probe_size);
	case SCTP_PLPMTUD_STATE_SEARCH:
		return sctp_plpmtud_search_on_probe_timeout(stcb, net, expired_probe_size);
	case SCTP_PLPMTUD_STATE_SEARCHCOMPLETE:
		return sctp_plpmtud_searchcomplete_on_probe_timeout(stcb, net, expired_probe_size);
	}
}

void
sctp_plpmtud_on_ptb_received(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t ptb_mtu)
{
	if (!net->plpmtud_use_ptb) {
		/* do nothing */
		return;
	}

	if (ptb_mtu < net->plpmtud_min_pmtu || ptb_mtu > net->plpmtud_max_pmtu) {
		/* PTB reports an MTU that is either smaller than minPMTU or larger than maxPMTU --> ignore PTB. */
		return;
	}

	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_BASE:
		return sctp_plpmtud_base_on_ptb_received(stcb, net, ptb_mtu);
	case SCTP_PLPMTUD_STATE_SEARCH:
		return sctp_plpmtud_search_on_ptb_received(stcb, net, ptb_mtu);
	case SCTP_PLPMTUD_STATE_SEARCHCOMPLETE:
		return sctp_plpmtud_searchcomplete_on_ptb_received(stcb, net, ptb_mtu);
	}
}

void
sctp_plpmtud_on_pmtu_invalid(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t largest_sctp_packet_acked_since_loss)
{
	uint32_t largest_acked_since_loss;

	largest_acked_since_loss = largest_sctp_packet_acked_since_loss + net->plpmtud_overhead;
	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_SEARCH:
		return sctp_plpmtud_search_on_pmtu_invalid(stcb, net, largest_acked_since_loss);
	case SCTP_PLPMTUD_STATE_SEARCHCOMPLETE:
		return sctp_plpmtud_searchcomplete_on_pmtu_invalid(stcb, net, largest_acked_since_loss);
	}
}

void
sctp_plpmtud_end(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_SEARCH:
		return sctp_plpmtud_search_end(stcb, net);
	}
}

static void
sctp_plpmtud_newstate(struct sctp_tcb *stcb, struct sctp_nets *net, uint8_t newstate)
{
	sctp_plpmtud_end(stcb, net);
	net->plpmtud_state = newstate;
	sctp_plpmtud_start(stcb, net);
}
