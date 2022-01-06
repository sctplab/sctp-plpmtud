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

enum
sctp_plpmtud_states
{
  DISABLED,
  BASE,
  ERROR,
  SEARCH,
  SEARCH_COMPLETE
};

static void
sctp_plpmtud_newstate(struct sctp_plpmtud *plpmtud, enum sctp_plpmtud_states newState);

void
sctp_plpmtud_init(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	uint32_t imtu;
	struct sctp_plpmtud *plpmtud;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: init\n");

	plpmtud = &(net->plpmtud);
	plpmtud->stcb = stcb;
	plpmtud->net = net;
	plpmtud->timer_value = 0;
	plpmtud->probed_size = 0;

	/* determine max_pmtu */
	plpmtud->max_pmtu = (SCTP_PLPMTUD_MAX_IP_SIZE >> 2) << 2;
	imtu = 0;
	if (net->ro._s_addr != NULL && net->ro._s_addr->ifn_p != NULL) {
		imtu = SCTP_GATHER_MTU_FROM_INTFC(net->ro._s_addr->ifn_p);
	}
	if (0 < imtu && imtu < plpmtud->max_pmtu) {
		plpmtud->max_pmtu = (imtu >> 2) << 2;
	}

	/* set min_pmtu, base_pmtu and overhead */
	switch (net->ro._l_addr.sa.sa_family) {
#ifdef INET
	case AF_INET:
		plpmtud->min_pmtu = (net->plpmtud_ipv4_min_mtu >> 2) << 2;
		plpmtud->base_pmtu = SCTP_PLPMTUD_BASE_IPV4;
		plpmtud->overhead = SCTP_MIN_V4_OVERHEAD;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		plpmtud->min_pmtu = (net->plpmtud_ipv6_min_mtu >> 2) << 2;
		plpmtud->base_pmtu = SCTP_PLPMTUD_BASE_IPV6;
		plpmtud->overhead = SCTP_MIN_OVERHEAD;
		break;
#endif
	default:
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: unknown address family, disable PLPMTUD\n");
		net->plpmtud_enabled = 0;
		return;
	}
	if (plpmtud->min_pmtu > plpmtud->max_pmtu) {
		plpmtud->min_pmtu = plpmtud->max_pmtu;
	}
	if (net->port) {
		plpmtud->overhead += (uint32_t)sizeof(struct udphdr);
	}

	plpmtud->initial_min_pmtu = plpmtud->min_pmtu;
	plpmtud->initial_max_pmtu = plpmtud->max_pmtu;

	sctp_plpmtud_newstate(plpmtud, DISABLED);
}

void
sctp_plpmtud_start(struct sctp_plpmtud *plpmtud)
{
	uint32_t rmtu, hcmtu;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: start\n");

	/* use MTU from route or from host cache as temporarily max_mtu */
	rmtu = hcmtu = 0;
	if (plpmtud->net->ro._s_addr != NULL) {
#if defined(__FreeBSD__) && !defined(__Userspace__)
		rmtu = SCTP_GATHER_MTU_FROM_ROUTE(plpmtud->net->ro._s_addr, &plpmtud->net->ro._l_addr.sa, plpmtud->net->ro.ro_nh);
		hcmtu = sctp_hc_get_mtu(&plpmtud->net->ro._l_addr, plpmtud->stcb->sctp_ep->fibnum);
#else
		rmtu = SCTP_GATHER_MTU_FROM_ROUTE(plpmtud->net->ro._s_addr, &plpmtud->net->ro._l_addr.sa, plpmtud->net->ro.ro_rt);
#endif
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: found rmtu=%u, hcmtu=%u\n", rmtu, hcmtu);

		if (0 < rmtu && rmtu < plpmtud->max_pmtu) {
			plpmtud->max_pmtu = (rmtu >> 2) << 2;
		}
		if (0 < hcmtu & hcmtu < plpmtud->max_pmtu) {
			plpmtud->max_pmtu = (hcmtu >> 2) << 2;
		}
		if (plpmtud->min_pmtu > plpmtud->max_pmtu) {
			plpmtud->min_pmtu = plpmtud->max_pmtu;
		}
	}

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: start with min_pmtu=%u, max_pmtu=%u, initial_min_pmtu=%u, initial_max_pmtu=%u, overhead=%u\n", plpmtud->min_pmtu, plpmtud->max_pmtu, plpmtud->initial_min_pmtu, plpmtud->initial_max_pmtu, plpmtud->overhead);
	sctp_plpmtud_newstate(plpmtud, BASE);
}

void
sctp_plpmtud_delayed_start(struct sctp_plpmtud *plpmtud)
{
	uint32_t delay, rndval, jitter;

	if (plpmtud->net->RTO == 0) {
		delay = plpmtud->stcb->asoc.initial_rto;
	} else {
		delay = plpmtud->net->RTO;
	}
	rndval = sctp_select_initial_TSN(&plpmtud->stcb->sctp_ep->sctp_ep);
	jitter = rndval % delay;
	if (delay > 1) {
		delay >>= 1;
	}
	if (delay < (UINT32_MAX - delay)) {
		delay += jitter;
	} else {
		delay = UINT32_MAX;
	}
	plpmtud->timer_value = delay;
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net);
}

void
sctp_plpmtud_on_probe_acked(struct sctp_plpmtud *plpmtud, uint32_t acked_probe_size)
{
	if (plpmtud->on_probe_acked != NULL) {
		plpmtud->on_probe_acked(plpmtud, acked_probe_size);
	}
}

void
sctp_plpmtud_on_probe_timeout(struct sctp_plpmtud *plpmtud)
{
	uint32_t expired_probe_size;
	if (plpmtud->on_probe_timeout != NULL) {
		expired_probe_size = plpmtud->probed_size;
		plpmtud->on_probe_timeout(plpmtud, expired_probe_size);
	}
}

void
sctp_plpmtud_on_ptb_received(struct sctp_plpmtud *plpmtud, uint32_t ptb_mtu)
{
	if (!plpmtud->net->plpmtud_use_ptb || plpmtud->on_ptb_received == NULL) {
		/* do nothing */
		return;
	}

	if (ptb_mtu < plpmtud->min_pmtu || ptb_mtu > plpmtud->max_pmtu) {
		/* PTB reports an MTU that is either smaller than minPMTU or larger than maxPMTU --> ignore PTB. */
		return;
	}

	plpmtud->on_ptb_received(plpmtud, ptb_mtu);
}

void
sctp_plpmtud_on_pmtu_invalid(struct sctp_plpmtud *plpmtud, uint32_t largest_sctp_packet_acked_since_loss)
{
	uint32_t largest_acked_since_loss;
	if (plpmtud->on_pmtu_invalid != NULL) {
		largest_acked_since_loss = largest_sctp_packet_acked_since_loss + plpmtud->overhead;
		plpmtud->on_pmtu_invalid(plpmtud, largest_acked_since_loss);
	}
}

static void
sctp_plpmtud_send_probe(struct sctp_plpmtud *plpmtud, uint32_t size, uint8_t rapid)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: send probe for %u at %u\n", size, sctp_get_tick_count());
	plpmtud->probe_count++;
	plpmtud->probed_size = size;
	sctp_send_plpmtud_probe(plpmtud->stcb, plpmtud->net, size, plpmtud->overhead);
	/* set probe timer
	 * srtt = lastsa >> SCTP_RTT_SHIFT = lastsa >> 3 = lastsa / 8
	 * rttvar = lastsv >> SCTP_RTT_VAR_SHIFT = lastsv >> 2 = lastsv / 4
	 * --> 4*rttvar = lastsv
	 */
	int clock_granularity = 2 * max(1, 1000/hz);
	uint32_t expected_response_time = (plpmtud->net->lastsa >> SCTP_RTT_SHIFT) + max(clock_granularity, plpmtud->net->lastsv);
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: expected_response_time = (%d >> %d) + max(2*%d, %d) = %d + %d = %u\n", plpmtud->net->lastsa, SCTP_RTT_SHIFT, clock_granularity, plpmtud->net->lastsv, (plpmtud->net->lastsa >> SCTP_RTT_SHIFT), max((2*clock_granularity), plpmtud->net->lastsv), expected_response_time);
	if (rapid) {
		plpmtud->timer_value = expected_response_time;
	} else {
		plpmtud->timer_value = max(expected_response_time, plpmtud->net->plpmtud_min_probe_rtx_time);
	}
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net);
}

static void
sctp_plpmtud_set_pmtu(struct sctp_plpmtud *plpmtud, uint32_t pmtu)
{
	uint32_t smallest_net_mtu, old_pmtu;
	struct sctp_nets *mnet;

	old_pmtu = plpmtud->net->mtu;
	plpmtud->net->mtu = pmtu;

	/* update smallest_mtu for the asoc */
	if (pmtu < plpmtud->stcb->asoc.smallest_mtu) {
		/* smallest_mtu reduced. */
		sctp_pathmtu_adjustment(plpmtud->stcb, pmtu, false);
	} else if (old_pmtu == plpmtud->stcb->asoc.smallest_mtu && pmtu > old_pmtu) {
		/* smallest_mtu might have been increased */
		/* find the new smallest mtu and use it */
		smallest_net_mtu = pmtu;
		TAILQ_FOREACH(mnet, &plpmtud->stcb->asoc.nets, sctp_next) {
			if (smallest_net_mtu < mnet->mtu) {
				smallest_net_mtu = mnet->mtu;
			}
		}
		plpmtud->stcb->asoc.smallest_mtu = smallest_net_mtu;
	}
}

static void
sctp_plpmtud_disabled_on_probe_timeout(struct sctp_plpmtud *plpmtud, uint32_t expired_probe_size)
{
	sctp_plpmtud_start(plpmtud);
}

static void
sctp_plpmtud_base_start(struct sctp_plpmtud *plpmtud)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE start\n");
	plpmtud->min_pmtu = plpmtud->initial_min_pmtu;
	sctp_plpmtud_set_pmtu(plpmtud, max(plpmtud->min_pmtu, plpmtud->base_pmtu));
	plpmtud->probe_count = 0;
	sctp_plpmtud_send_probe(plpmtud, max(plpmtud->min_pmtu, plpmtud->base_pmtu), 0);
}

static void
sctp_plpmtud_base_on_probe_acked(struct sctp_plpmtud *plpmtud, uint32_t acked_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE %u acked\n", acked_probe_size);
	if (acked_probe_size < plpmtud->base_pmtu) {
		/* ignore ack */
		return;
	}
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_1);
	if (acked_probe_size < plpmtud->max_pmtu) {
		plpmtud->min_pmtu = acked_probe_size;
		sctp_plpmtud_newstate(plpmtud, SEARCH);
	} else {
		sctp_plpmtud_newstate(plpmtud, SEARCH_COMPLETE);
	}
}

static void
sctp_plpmtud_base_on_probe_timeout(struct sctp_plpmtud *plpmtud, uint32_t expired_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE %u expired\n", expired_probe_size);
	if (plpmtud->probe_count < plpmtud->net->plpmtud_max_probes) {
		sctp_plpmtud_send_probe(plpmtud, expired_probe_size, 0);
	} else {
		sctp_plpmtud_newstate(plpmtud, ERROR);
	}
}

static void
sctp_plpmtud_base_on_ptb_received(struct sctp_plpmtud *plpmtud, uint32_t ptb_mtu)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE PTB received reporting an MTU of %u\n", ptb_mtu);
	if (plpmtud->min_pmtu <= ptb_mtu && ptb_mtu < plpmtud->base_pmtu) {
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_1);
		sctp_plpmtud_newstate(plpmtud, ERROR);
	}
}

static void
sctp_plpmtud_error_start(struct sctp_plpmtud *plpmtud)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR start\n");
	plpmtud->min_pmtu = plpmtud->initial_min_pmtu;
	sctp_plpmtud_set_pmtu(plpmtud, plpmtud->min_pmtu);
	if (plpmtud->probed_size > plpmtud->min_pmtu) {
		plpmtud->probe_count = 0;
		sctp_plpmtud_send_probe(plpmtud, plpmtud->min_pmtu, 0);
	} else {
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR min pmtu %u was already probed without success, stop.\n", plpmtud->min_pmtu);
	}
}

static void
sctp_plpmtud_error_on_probe_acked(struct sctp_plpmtud *plpmtud, uint32_t acked_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR %u acked\n", acked_probe_size);
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_1);
	sctp_plpmtud_newstate(plpmtud, SEARCH);
}

static void
sctp_plpmtud_error_on_probe_timeout(struct sctp_plpmtud *plpmtud, uint32_t expired_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR %u expired\n", expired_probe_size);
	if (plpmtud->probe_count < plpmtud->net->plpmtud_max_probes) {
		sctp_plpmtud_send_probe(plpmtud, plpmtud->min_pmtu, 0);
	} else {
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR probe for min pmtu %u failed, stop.\n", plpmtud->min_pmtu);
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
sctp_plpmtud_search_up_get_next_candidate(struct sctp_plpmtud *plpmtud)
{
	uint32_t next = plpmtud->net->mtu + SCTP_PLPMTUD_STEPSIZE;
	if (next >= plpmtud->smallest_failed
	 || next > plpmtud->smallest_expired
	 || next > plpmtud->max_pmtu) {
		return 0;
	}
	return next;
}

static uint32_t
sctp_plpmtud_search_optbinary_get_next_candidate(struct sctp_plpmtud *plpmtud)
{
	if (plpmtud->net->mtu == plpmtud->min_pmtu && plpmtud->smallest_expired == SCTP_PLPMTUD_MAX_IP_SIZE) {
		/* start optimistic */
		return plpmtud->max_pmtu;
	}
	uint32_t min = plpmtud->net->mtu;
	uint32_t max = plpmtud->max_pmtu;
	if (max > plpmtud->smallest_failed - SCTP_PLPMTUD_STEPSIZE) {
		max = plpmtud->smallest_failed - SCTP_PLPMTUD_STEPSIZE;
	}
	if (max > plpmtud->smallest_expired) {
		max = plpmtud->smallest_expired;
	}
	/* ceil(((double)(max - min)) / (SCTP_PLPMTUD_STEPSIZE * 2)) * SCTP_PLPMTUD_STEPSIZE + min; */
	uint32_t next = ((max - min + SCTP_PLPMTUD_STEPSIZE * 2 - 1) / (SCTP_PLPMTUD_STEPSIZE * 2)) * SCTP_PLPMTUD_STEPSIZE + min;
	if (next == plpmtud->net->mtu) {
		return 0;
	}
	return next;
}

static void
sctp_plpmtud_search_send_probe(struct sctp_plpmtud *plpmtud, uint32_t size)
{
	uint8_t rapid;

	sctp_plpmtud_search_add_probe(&(plpmtud->probes), size);

	rapid = 0;
	if (plpmtud->last_probe_acked) {
		/* the last probe packet was acked, which gives us confidence in the estimated RTT */
		rapid = 1;
	} else {
		struct sctp_plpmtud_probe *smallest = sctp_plpmtud_search_get_smallest_probe(&(plpmtud->probes));
		if (smallest->size > plpmtud->net->mtu + SCTP_PLPMTUD_STEPSIZE) {
			/* we still have the possibility to probe for smaller candidates */
			rapid = 1;
		}
	}
	sctp_plpmtud_send_probe(plpmtud, size, rapid);
}

static void
sctp_plpmtud_search_start(struct sctp_plpmtud *plpmtud)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH start\n");
	plpmtud->last_probe_acked = 0;
	plpmtud->smallest_expired = SCTP_PLPMTUD_MAX_IP_SIZE;
	plpmtud->smallest_failed = SCTP_PLPMTUD_MAX_IP_SIZE;

	switch(plpmtud->net->plpmtud_search_algorithm) {
	case SCTP_PLPMTUD_ALGORITHM_UP:
		plpmtud->get_next_candidate = &sctp_plpmtud_search_up_get_next_candidate;
		break;
	default:
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: No search algorithm with ID %u, use OptBinary\n", plpmtud->net->plpmtud_search_algorithm);
	case SCTP_PLPMTUD_ALGORITHM_OPTBINARY:
		plpmtud->get_next_candidate = &sctp_plpmtud_search_optbinary_get_next_candidate;
		break;
	}

	TAILQ_INIT(&(plpmtud->probes));

	uint32_t first = plpmtud->get_next_candidate(plpmtud);
	sctp_plpmtud_search_send_probe(plpmtud, first);
}

static void
sctp_plpmtud_search_on_probe_acked(struct sctp_plpmtud *plpmtud, uint32_t acked_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH %u acked at %u\n", acked_probe_size, sctp_get_tick_count());
	if (acked_probe_size < plpmtud->net->mtu) {
		/* ignore ack */
		return;
	}
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_2);
	plpmtud->last_probe_acked = 1;
	sctp_plpmtud_set_pmtu(plpmtud, acked_probe_size);
	if (plpmtud->net->mtu >= plpmtud->max_pmtu) {
		/* max PMTU acked, transistion to SEARCH_COMPLETE */
		return sctp_plpmtud_newstate(plpmtud, SEARCH_COMPLETE);
	}
	sctp_plpmtud_search_remove_probes(&(plpmtud->probes), acked_probe_size, 1, 1, 0);
	if (acked_probe_size >= plpmtud->smallest_expired) {
		/* update smallest expired */
		struct sctp_plpmtud_probe *smallest = sctp_plpmtud_search_get_smallest_probe(&(plpmtud->probes));
		if (smallest == NULL) {
			plpmtud->smallest_expired = SCTP_PLPMTUD_MAX_IP_SIZE;
		} else {
			plpmtud->smallest_expired = smallest->size;
		}
	}

	uint32_t probe_size = plpmtud->get_next_candidate(plpmtud);
	if (probe_size > 0) {
		sctp_plpmtud_search_send_probe(plpmtud, probe_size);
	} else {
		sctp_plpmtud_newstate(plpmtud, SEARCH_COMPLETE);
	}
}

static void
sctp_plpmtud_search_on_probe_timeout(struct sctp_plpmtud *plpmtud, uint32_t expired_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH %u expired at %u\n", expired_probe_size, sctp_get_tick_count());
	plpmtud->last_probe_acked = 0;
	plpmtud->smallest_expired = expired_probe_size;

	struct sctp_plpmtud_probe *probe = sctp_plpmtud_search_get_probe(&(plpmtud->probes), expired_probe_size);
	if (probe->count == plpmtud->net->plpmtud_max_probes) {
		plpmtud->smallest_failed = expired_probe_size;
		sctp_plpmtud_search_remove_probes(&(plpmtud->probes), expired_probe_size, 0, 1, 1);
	}

	/* try to send a new probe packet */
	uint32_t probe_size = plpmtud->get_next_candidate(plpmtud);
	if (probe_size > 0) {
		sctp_plpmtud_search_send_probe(plpmtud, probe_size);
	} else {
		sctp_plpmtud_newstate(plpmtud, SEARCH_COMPLETE);
	}
}

static void
sctp_plpmtud_search_on_ptb_received(struct sctp_plpmtud *plpmtud, uint32_t ptb_mtu)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH PTB received reporting an MTU of %u\n", ptb_mtu);
	/* correct ptbMtu to the next smaller multiple of 4 */
	ptb_mtu = (ptb_mtu >> 2) << 2;
	if (ptb_mtu < plpmtud->net->mtu) {
		/* reported MTU is smaller than a previously successful probed size. Go back to BASE. */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_3);
		sctp_plpmtud_newstate(plpmtud, BASE);
	} else if (ptb_mtu == plpmtud->net->mtu) {
		/* reported MTU confirmed current PMTU. Transition to SEARCH_COMPLETE */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_4);
		sctp_plpmtud_newstate(plpmtud, SEARCH_COMPLETE);
	} else if (!sctp_plpmtud_search_exists_larger_probe(&(plpmtud->probes), ptb_mtu)) {
		/* no probe sent that would trigger this PTB, ignore. */
	} else {
		/* PMTU < PTB_MTU < MAX_PMTU */
		/* use reported MTU for a new probe */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_5);
		plpmtud->last_probe_acked = 0;
		plpmtud->max_pmtu = ptb_mtu;
		sctp_plpmtud_search_remove_probes(&(plpmtud->probes), ptb_mtu, 0, 0, 1);
		if (sctp_plpmtud_search_get_probe(&(plpmtud->probes), ptb_mtu) == NULL) {
			sctp_plpmtud_search_send_probe(plpmtud, ptb_mtu);
		}
	}
}

static void
sctp_plpmtud_search_on_pmtu_invalid(struct sctp_plpmtud *plpmtud, uint32_t largest_acked_since_loss)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH PMTU reported invalid with largestAckedSinceLoss=%u\n", largest_acked_since_loss);
	/* return to BASE */
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_6);
	sctp_plpmtud_newstate(plpmtud, BASE);
}

static void
sctp_plpmtud_search_end(struct sctp_plpmtud *plpmtud)
{
	/* cleanup probes list */
	sctp_plpmtud_search_remove_probes(&(plpmtud->probes), 0, 1, 1, 1);
}

static void
sctp_plpmtud_searchcomplete_start(struct sctp_plpmtud *plpmtud)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE start\n");
	plpmtud->min_pmtu = plpmtud->initial_min_pmtu;
	plpmtud->max_pmtu = plpmtud->initial_max_pmtu;

	/* write discovered PMTU into the host cache (FreeBSD) or set it for the route */
	if (plpmtud->net->ro._s_addr != NULL) {
#if defined(__FreeBSD__) && !defined(__Userspace__)
		sctp_hc_set_mtu(&plpmtud->net->ro._l_addr, plpmtud->stcb->sctp_ep->fibnum, plpmtud->net->mtu);
#else
		SCTP_SET_MTU_OF_ROUTE(&plpmtud->net->ro._l_addr.sa, plpmtud->net->ro.ro_rt, plpmtud->net->mtu);
#endif
	}

	if (plpmtud->net->mtu < plpmtud->max_pmtu) {
		plpmtud->probed_size = 0;
		plpmtud->timer_value = plpmtud->net->plpmtud_raise_time;
		sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net);
	}
}

static void
sctp_plpmtud_searchcomplete_on_probe_acked(struct sctp_plpmtud *plpmtud, uint32_t acked_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE %u acked\n", acked_probe_size);
	if (acked_probe_size <= plpmtud->net->mtu) {
		/* ignore ack */
		return;
	}

	/* PMTU increased */
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_7);
	sctp_plpmtud_set_pmtu(plpmtud, acked_probe_size);
	if (plpmtud->net->mtu < plpmtud->max_pmtu) {
		plpmtud->min_pmtu = acked_probe_size;
		sctp_plpmtud_newstate(plpmtud, SEARCH);
	}
}

static void
sctp_plpmtud_searchcomplete_on_probe_timeout(struct sctp_plpmtud *plpmtud, uint32_t expired_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE %u expired\n", expired_probe_size);
	if (expired_probe_size == 0) {
		/* raise timer fired */
		uint32_t next = plpmtud->net->mtu + SCTP_PLPMTUD_STEPSIZE;
		if (next > plpmtud->max_pmtu) {
			next = plpmtud->max_pmtu;
		}
		plpmtud->probe_count = 0;
		sctp_plpmtud_send_probe(plpmtud, next, 0);
	} else {
		/* raise probe expired */
		if (plpmtud->probe_count < plpmtud->net->plpmtud_max_probes) {
			sctp_plpmtud_send_probe(plpmtud, expired_probe_size, 0);
		} else {
			/* give up, reschedule raise timer */
			plpmtud->probed_size = 0;
			plpmtud->timer_value = plpmtud->net->plpmtud_raise_time;
			sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net);
		}
	}
}

static void
sctp_plpmtud_searchcomplete_on_ptb_received(struct sctp_plpmtud *plpmtud, uint32_t ptb_mtu)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE PTB received reporting an MTU of %u\n", ptb_mtu);
	/* correct ptbMtu to the next smaller multiple of 4 */
	ptb_mtu = (ptb_mtu >> 2) << 2;
	if (ptb_mtu < plpmtud->net->mtu) {
		/* reported MTU is smaller than the current PMTU. Go back to BASE. */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_8);
		plpmtud->max_pmtu = ptb_mtu;
		sctp_plpmtud_newstate(plpmtud, BASE);
	} else if (ptb_mtu == plpmtud->net->mtu) {
		/* reported MTU confirmed the current PMTU. Reschedule RAISE_TIMER */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net, SCTP_FROM_SCTPUTIL + SCTP_LOC_9);
		plpmtud->probed_size = 0;
		plpmtud->timer_value = plpmtud->net->plpmtud_raise_time;
		sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, plpmtud->stcb->sctp_ep, plpmtud->stcb, plpmtud->net);
	} /* else {
		no probe outstanding or
		reported MTU is equal or larger than the currently probed size or
		PMTU < ptbMtu < PMTU+4
		--> ignore PTB.
	} */
}

static void
sctp_plpmtud_searchcomplete_on_pmtu_invalid(struct sctp_plpmtud *plpmtud, uint32_t largest_acked_since_loss)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE PMTU reported invalid with largest_acked_since_loss=%u\n", largest_acked_since_loss);
	plpmtud->max_pmtu = plpmtud->net->mtu;
	if (largest_acked_since_loss >= plpmtud->min_pmtu) {
		plpmtud->min_pmtu = largest_acked_since_loss;
		sctp_plpmtud_set_pmtu(plpmtud, largest_acked_since_loss);
		sctp_plpmtud_newstate(plpmtud, SEARCH);
	} else {
		sctp_plpmtud_newstate(plpmtud, BASE);
	}
}

static void
sctp_plpmtud_newstate(struct sctp_plpmtud *plpmtud, enum sctp_plpmtud_states newstate)
{
	if (plpmtud->end != NULL) {
		plpmtud->end(plpmtud);
	}
	if (newstate == DISABLED) {
		plpmtud->start = NULL;
		plpmtud->on_probe_acked = NULL;
		plpmtud->on_probe_timeout = &sctp_plpmtud_disabled_on_probe_timeout;
		plpmtud->on_ptb_received = NULL;
		plpmtud->on_pmtu_invalid = NULL;
		plpmtud->end = NULL;
	} else if (newstate == BASE) {
		plpmtud->start = &sctp_plpmtud_base_start;
		plpmtud->on_probe_acked = &sctp_plpmtud_base_on_probe_acked;
		plpmtud->on_probe_timeout = &sctp_plpmtud_base_on_probe_timeout;
		plpmtud->on_ptb_received = sctp_plpmtud_base_on_ptb_received;
		plpmtud->on_pmtu_invalid = NULL;
		plpmtud->end = NULL;
	} else if (newstate == ERROR) {
		plpmtud->start = &sctp_plpmtud_error_start;
		plpmtud->on_probe_acked = &sctp_plpmtud_error_on_probe_acked;
		plpmtud->on_probe_timeout = &sctp_plpmtud_error_on_probe_timeout;
		plpmtud->on_ptb_received = NULL;
		plpmtud->on_pmtu_invalid = NULL;
		plpmtud->end = NULL;
	} else if (newstate == SEARCH) {
		plpmtud->start = &sctp_plpmtud_search_start;
		plpmtud->on_probe_acked = &sctp_plpmtud_search_on_probe_acked;
		plpmtud->on_probe_timeout = &sctp_plpmtud_search_on_probe_timeout;
		plpmtud->on_ptb_received = sctp_plpmtud_search_on_ptb_received;
		plpmtud->on_pmtu_invalid = sctp_plpmtud_search_on_pmtu_invalid;
		plpmtud->end = &sctp_plpmtud_search_end;
	} else if (newstate == SEARCH_COMPLETE) {
		plpmtud->start = &sctp_plpmtud_searchcomplete_start;
		plpmtud->on_probe_acked = &sctp_plpmtud_searchcomplete_on_probe_acked;
		plpmtud->on_probe_timeout = &sctp_plpmtud_searchcomplete_on_probe_timeout;
		plpmtud->on_ptb_received = sctp_plpmtud_searchcomplete_on_ptb_received;
		plpmtud->on_pmtu_invalid = sctp_plpmtud_searchcomplete_on_pmtu_invalid;
		plpmtud->end = NULL;
	}
	if (plpmtud->start != NULL) {
		plpmtud->start(plpmtud);
	}
}
