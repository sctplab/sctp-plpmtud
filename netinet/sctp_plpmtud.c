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
#endif
#if defined(INET) || defined(INET6)
#if !defined(_WIN32)
#include <netinet/udp.h>
#endif
#endif

static void
sctp_plpmtud_newstate(struct sctp_tcb *, struct sctp_nets *, uint8_t);

static uint32_t
sctp_plpmtud_get_overhead(struct sctp_nets *net)
{
	uint32_t overhead;

	overhead = 0;
	switch (net->ro._l_addr.sa.sa_family) {
#ifdef INET
	case AF_INET:
		overhead = SCTP_MIN_V4_OVERHEAD;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		overhead = SCTP_MIN_OVERHEAD;
		break;
#endif
	}

#if defined(INET) || defined(INET6)
	if (net->port) {
		overhead += (uint32_t)sizeof(struct udphdr);
	}
#endif

	return overhead;
}

static struct sctp_plpmtud_probe *
sctp_plpmtud_add_probe(struct sctp_plpmtud_probe_head *head, uint32_t size, struct sctp_pcb *inp)
{
	struct sctp_plpmtud_probe *probe;
	uint32_t id;

	do {
		do {
			id = sctp_select_initial_TSN(inp);
		} while (id == 0);
		TAILQ_FOREACH(probe, head, next) {
			if (probe->size == size) {
				/* move probe to the end of the list */
				TAILQ_REMOVE(head, probe, next);
				TAILQ_INSERT_TAIL(head, probe, next);
				return probe;
			}
			if (probe->id == id) {
				id = 0;
				break;
			}
		}
	} while (id == 0);

	probe = SCTP_ZONE_GET(SCTP_BASE_INFO(ipi_zone_net), struct sctp_plpmtud_probe);
	probe->id = id;
	probe->size = size;
	probe->count = 0;
	TAILQ_INSERT_TAIL(head, probe, next);

	return probe;
}

static bool
sctp_plpmtud_exists_probe(struct sctp_plpmtud_probe_head *head, uint32_t size)
{
	struct sctp_plpmtud_probe *probe;

	TAILQ_FOREACH(probe, head, next) {
		if (probe->size == size) {
			return true;
		}
	}
	return false;
}

static struct sctp_plpmtud_probe *
sctp_plpmtud_get_probe(struct sctp_plpmtud_probe_head *head, uint32_t id)
{
	struct sctp_plpmtud_probe *probe;

	TAILQ_FOREACH_REVERSE(probe, head, sctp_plpmtud_probe_head, next) {
		if (probe->id == id) {
			return probe;
		}
	}
	return NULL;
}

static void
sctp_plpmtud_delete_probe(struct sctp_plpmtud_probe_head *head, struct sctp_plpmtud_probe *probe)
{
	TAILQ_REMOVE(head, probe, next);
	SCTP_ZONE_FREE(SCTP_BASE_INFO(ipi_zone_net), probe);
}

static void
sctp_plpmtud_send_probe(struct sctp_tcb *stcb, struct sctp_nets *net, struct sctp_plpmtud_probe *probe, bool rapid)
{
	int clock_granularity;
	uint32_t expected_response_time, route_mtu;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: send probe for %u at %u\n", probe->size, sctp_get_tick_count());

	net->plpmtud_last_probe = probe;
	probe->count++;
	route_mtu = sctp_route_get_mtu(net);
	if (0 < route_mtu && route_mtu < probe->size) {
		sctp_route_set_mtu(net, probe->size);
	}
	sctp_send_plpmtud_probe(stcb, net, probe->size, sctp_plpmtud_get_overhead(net), probe->id);
	if (0 < route_mtu && route_mtu < probe->size) {
		sctp_route_set_mtu(net, route_mtu);
	}
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

static uint32_t
sctp_plpmtud_get_pmtu(struct sctp_nets *net)
{
	uint32_t pmtu;

	pmtu = net->mtu;
#if defined(INET) || defined(INET6)
	if (net->port) {
		pmtu += (uint32_t)sizeof(struct udphdr);
	}
#endif
	return pmtu;
}

static void
sctp_plpmtud_set_pmtu(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t pmtu, bool resend)
{
	uint32_t smallest_net_mtu, old_pmtu;
	struct sctp_nets *mnet;

#if defined(INET) || defined(INET6)
	if (net->port) {
		pmtu -= (uint32_t)sizeof(struct udphdr);
	}
#endif
	old_pmtu = net->mtu;
	net->mtu = pmtu;

	/* update smallest_mtu for the asoc */
	if (pmtu < stcb->asoc.smallest_mtu) {
		/* smallest_mtu reduced. */
		sctp_pathmtu_adjustment(stcb, pmtu, resend);
		if (resend) {
			sctp_chunk_output(stcb->sctp_ep, stcb, SCTP_OUTPUT_FROM_PLPMTUD, SCTP_SO_LOCKED);
		}
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
sctp_plpmtud_cache_pmtu(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t pmtu, bool increase)
{
	if (net->ro._s_addr != NULL) {
#if defined(__FreeBSD__) && !defined(__Userspace__)
		if (pmtu < sctp_hc_get_mtu(&net->ro._l_addr, stcb->sctp_ep->fibnum) || increase) {
			sctp_hc_set_mtu(&net->ro._l_addr, stcb->sctp_ep->fibnum, pmtu);
		}
#endif
		if (pmtu < sctp_route_get_mtu(net) || increase) {
			sctp_route_set_mtu(net, pmtu);
		}
	}
}

static uint32_t
sctp_plpmtud_get_upper_limit(struct sctp_nets *net)
{
	uint32_t imtu, upper_limit;

	/* determine upper_limit */
	upper_limit = (SCTP_PLPMTUD_MAX_IP_SIZE >> 2) << 2;
	imtu = 0;
	if (net->ro._s_addr != NULL && net->ro._s_addr->ifn_p != NULL) {
		imtu = SCTP_GATHER_MTU_FROM_IFN_INFO(net->ro._s_addr->ifn_p->ifn_p, net->ro._s_addr->ifn_p->ifn_index);
	}
	if (0 < imtu && imtu < upper_limit) {
		upper_limit = (imtu >> 2) << 2;
	}

	return upper_limit;
}

static uint32_t
sctp_plpmtud_get_lower_limit(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t upper_limit)
{
	uint32_t lower_limit;

	switch (net->ro._l_addr.sa.sa_family) {
#ifdef INET
	case AF_INET:
		lower_limit = (stcb->asoc.plpmtud_ipv4_min_mtu >> 2) << 2;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		lower_limit = (stcb->asoc.plpmtud_ipv6_min_mtu >> 2) << 2;
		break;
#endif
	}

	/* reduce lower_limit if it exceeds upper_limit */
	if (lower_limit > upper_limit) {
		lower_limit = upper_limit;
	}

	return lower_limit;
}

static uint32_t
sctp_plpmtud_get_base(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t min_pmtu, uint32_t max_pmtu)
{
	uint32_t base;

	switch (net->ro._l_addr.sa.sa_family) {
#ifdef INET
	case AF_INET:
		base = SCTP_PLPMTUD_BASE_IPV4;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		base = SCTP_PLPMTUD_BASE_IPV6;
		break;
#endif
	}

	return min( max(base, min_pmtu), max_pmtu );
}

static uint32_t
sctp_plpmtud_find_smaller_max(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t lower_limit, uint32_t max_pmtu)
{
	uint32_t route_mtu, hc_mtu, nd_mtu;

	/* use MTU from route, host cache and neighbor discovery to reduce max */
	route_mtu = hc_mtu = nd_mtu = 0;
	if (net->ro._s_addr != NULL) {
		route_mtu = sctp_route_get_mtu(net);
#if defined(__FreeBSD__) && !defined(__Userspace__)
		hc_mtu = sctp_hc_get_mtu(&net->ro._l_addr, stcb->sctp_ep->fibnum);
#endif
#ifdef INET6
#if !defined(__Userspace__)
		struct ifnet *ifp;

		ifp = SCTP_GET_IFN_VOID_FROM_ROUTE( (&net->ro) );
		if (ifp != NULL) {
#if defined(_WIN32)
#define ND_IFINFO(ifp)	(ifp)
#define linkmtu		if_mtu
#endif
			nd_mtu = ND_IFINFO(ifp)->linkmtu;
		}
#endif
#endif
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: found route_mtu=%u, hc_mtu=%u, nd_mtu=%u\n", route_mtu, hc_mtu, nd_mtu);

		if (lower_limit <= route_mtu && route_mtu < max_pmtu) {
			max_pmtu = (route_mtu >> 2) << 2;
		}
		if (lower_limit <= hc_mtu & hc_mtu < max_pmtu) {
			max_pmtu = (hc_mtu >> 2) << 2;
		}
		if (lower_limit <= nd_mtu & nd_mtu < max_pmtu) {
			max_pmtu = (nd_mtu >> 2) << 2;
		}
	}

	return max_pmtu;
}

static void
sctp_plpmtud_base_begin(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	uint32_t upper_limit;
	struct sctp_plpmtud_probe *probe;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE begin\n");

	upper_limit = sctp_plpmtud_get_upper_limit(net);
	net->plpmtud_min_pmtu = sctp_plpmtud_get_lower_limit(stcb, net, upper_limit);
	net->plpmtud_max_pmtu = sctp_plpmtud_find_smaller_max(stcb, net, net->plpmtud_min_pmtu, min(net->plpmtud_max_pmtu, upper_limit));
	net->plpmtud_base_pmtu = sctp_plpmtud_get_base(stcb, net, net->plpmtud_min_pmtu, net->plpmtud_max_pmtu);

	sctp_plpmtud_set_pmtu(stcb, net, net->plpmtud_base_pmtu, false);
	probe = sctp_plpmtud_add_probe(&(net->plpmtud_probes), net->plpmtud_base_pmtu, &(stcb->sctp_ep->sctp_ep));
	sctp_plpmtud_send_probe(stcb, net, probe, false);
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
	sctp_plpmtud_set_pmtu(stcb, net, acked_probe_size, false);
	if (acked_probe_size < net->plpmtud_max_pmtu) {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCH);
	} else {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCHCOMPLETE);
	}
}

static void
sctp_plpmtud_base_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net, struct sctp_plpmtud_probe *expired_probe)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE %u expired\n", expired_probe->size);
	if (expired_probe->count < net->plpmtud_max_probes) {
		sctp_plpmtud_send_probe(stcb, net, expired_probe, false);
	} else {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_ERROR);
	}
}

static void
sctp_plpmtud_base_on_ptb_received(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t ptb_mtu)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: BASE PTB received reporting an MTU of %u\n", ptb_mtu);
	if (ptb_mtu < net->plpmtud_base_pmtu) {
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_2);
		net->plpmtud_max_pmtu = ptb_mtu;
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_ERROR);
	}
}

static void
sctp_plpmtud_error_begin(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	struct sctp_plpmtud_probe *probe;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR begin\n");

	net->plpmtud_min_pmtu = sctp_plpmtud_get_lower_limit(stcb, net, sctp_plpmtud_get_upper_limit(net));

	sctp_plpmtud_set_pmtu(stcb, net, net->plpmtud_min_pmtu, false);
	if (sctp_plpmtud_exists_probe(&(net->plpmtud_probes), net->plpmtud_min_pmtu)) {
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR min pmtu %u was already probed without success, stop.\n", net->plpmtud_min_pmtu);
		sctp_plpmtud_stop(stcb, net);
	} else {
		probe = sctp_plpmtud_add_probe(&(net->plpmtud_probes), net->plpmtud_min_pmtu, &(stcb->sctp_ep->sctp_ep));
		sctp_plpmtud_send_probe(stcb, net, probe, false);
	}
}

static void
sctp_plpmtud_error_on_probe_acked(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t acked_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR %u acked\n", acked_probe_size);
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_3);
	sctp_plpmtud_set_pmtu(stcb, net, acked_probe_size, false);
	if (acked_probe_size < net->plpmtud_max_pmtu) {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCH);
	} else {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCHCOMPLETE);
	}
}

static void
sctp_plpmtud_error_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net, struct sctp_plpmtud_probe *expired_probe)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR %u expired\n", expired_probe->size);
	if (expired_probe->count < net->plpmtud_max_probes) {
		sctp_plpmtud_send_probe(stcb, net, expired_probe, false);
	} else {
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: ERROR probe for min pmtu %u failed, stop.\n", net->plpmtud_min_pmtu);
		sctp_plpmtud_stop(stcb, net);
	}
}

static void
sctp_plpmtud_search_delete_probes(struct sctp_plpmtud_probe_head *head, uint32_t size, bool smaller, bool equal, bool larger)
{
	struct sctp_plpmtud_probe *probe, *temp;

	TAILQ_FOREACH_SAFE(probe, head, next, temp) {
		if ((equal && probe->size == size)
		 || (larger && probe->size > size)
		 || (smaller && probe->size < size)) {

			sctp_plpmtud_delete_probe(head, probe);
		}
	}
}

static struct sctp_plpmtud_probe *
sctp_plpmtud_search_get_smallest_probe(struct sctp_plpmtud_probe_head *head)
{
	struct sctp_plpmtud_probe *probe;
	struct sctp_plpmtud_probe *smallest;

	smallest = TAILQ_FIRST(head);
	TAILQ_FOREACH(probe, head, next) {
		if (probe->size < smallest->size) {
			smallest = probe;
		}
	}
	return smallest;
}

static bool
sctp_plpmtud_search_exists_larger_probe(struct sctp_plpmtud_probe_head *head, uint32_t size)
{
	struct sctp_plpmtud_probe *probe;

	TAILQ_FOREACH(probe, head, next) {
		if (probe->size > size) {
			return true;
		}
	}
	return false;
}

static uint32_t
sctp_plpmtud_search_up_get_next_candidate(struct sctp_tcb *stcb, struct sctp_nets *net, bool first)
{
	uint32_t next;

	next = sctp_plpmtud_get_pmtu(net) + SCTP_PLPMTUD_STEPSIZE;
	if (next >= net->plpmtud_smallest_failed
	 || next > net->plpmtud_smallest_expired
	 || next > net->plpmtud_max_pmtu) {
		return 0;
	}
	return next;
}

static uint32_t
sctp_plpmtud_search_optbinary_get_next_candidate(struct sctp_tcb *stcb, struct sctp_nets *net, bool first)
{
	uint32_t min, max, next;

	if (first) {
		/* start optimistic */
		return net->plpmtud_max_pmtu;
	}
	min = sctp_plpmtud_get_pmtu(net);
	max = net->plpmtud_max_pmtu;
	if (max > net->plpmtud_smallest_failed - SCTP_PLPMTUD_STEPSIZE) {
		max = net->plpmtud_smallest_failed - SCTP_PLPMTUD_STEPSIZE;
	}
	if (max > net->plpmtud_smallest_expired) {
		max = net->plpmtud_smallest_expired;
	}
	/* ceil(((double)(max - min)) / (SCTP_PLPMTUD_STEPSIZE * 2)) * SCTP_PLPMTUD_STEPSIZE + min; */
	next = ((max - min + SCTP_PLPMTUD_STEPSIZE * 2 - 1) / (SCTP_PLPMTUD_STEPSIZE * 2)) * SCTP_PLPMTUD_STEPSIZE + min;
	if (next == sctp_plpmtud_get_pmtu(net)) {
		return 0;
	}
	return next;
}

static void
sctp_plpmtud_search_send_probe(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t size)
{
	struct sctp_plpmtud_probe *probe;
	bool rapid;

	probe = sctp_plpmtud_add_probe(&(net->plpmtud_probes), size, &(stcb->sctp_ep->sctp_ep));
	rapid = false;
	if (net->plpmtud_last_probe_acked) {
		/* the last probe packet was acked, which gives us confidence in the estimated RTT */
		rapid = true;
	} else {
		struct sctp_plpmtud_probe *smallest = sctp_plpmtud_search_get_smallest_probe(&(net->plpmtud_probes));
		if (smallest->size > sctp_plpmtud_get_pmtu(net) + SCTP_PLPMTUD_STEPSIZE) {
			/* we still have the possibility to probe for smaller candidates */
			rapid = true;
		}
	}
	sctp_plpmtud_send_probe(stcb, net, probe, rapid);
}

static void
sctp_plpmtud_search_begin(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	uint32_t probe_size;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH begin\n");
	net->plpmtud_last_probe_acked = false;
	net->plpmtud_smallest_expired = SCTP_PLPMTUD_MAX_IP_SIZE;
	net->plpmtud_smallest_failed = SCTP_PLPMTUD_MAX_IP_SIZE;
	/* cleanup probes list */
	sctp_plpmtud_search_delete_probes(&(net->plpmtud_probes), 0, true, true, true);

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

	probe_size = net->plpmtud_get_next_candidate(stcb, net, true);
	sctp_plpmtud_search_send_probe(stcb, net, probe_size);
}

static void
sctp_plpmtud_search_on_probe_acked(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t acked_probe_size)
{
	struct sctp_plpmtud_probe *smallest;
	uint32_t probe_size;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH %u acked at %u\n", acked_probe_size, sctp_get_tick_count());
	if (acked_probe_size < sctp_plpmtud_get_pmtu(net)) {
		/* ignore ack */
		return;
	}
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_4);
	net->plpmtud_last_probe_acked = true;
	sctp_plpmtud_set_pmtu(stcb, net, acked_probe_size, false);
	if (sctp_plpmtud_get_pmtu(net) >= net->plpmtud_max_pmtu) {
		/* max PMTU acked, transistion to SEARCH_COMPLETE */
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCHCOMPLETE);
		return;
	}
	sctp_plpmtud_search_delete_probes(&(net->plpmtud_probes), acked_probe_size, true, true, false);
	if (acked_probe_size >= net->plpmtud_smallest_expired) {
		/* update smallest expired */
		smallest = sctp_plpmtud_search_get_smallest_probe(&(net->plpmtud_probes));
		if (smallest == NULL) {
			net->plpmtud_smallest_expired = SCTP_PLPMTUD_MAX_IP_SIZE;
		} else {
			net->plpmtud_smallest_expired = smallest->size;
		}
	}

	probe_size = net->plpmtud_get_next_candidate(stcb, net, false);
	if (probe_size > 0) {
		sctp_plpmtud_search_send_probe(stcb, net, probe_size);
	} else {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCHCOMPLETE);
	}
}

static void
sctp_plpmtud_search_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net, struct sctp_plpmtud_probe *expired_probe)
{
	uint32_t probe_size;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH %u expired at %u\n", expired_probe->size, sctp_get_tick_count());
	net->plpmtud_last_probe_acked = false;
	net->plpmtud_smallest_expired = expired_probe->size;

	if (expired_probe->count == net->plpmtud_max_probes) {
		net->plpmtud_smallest_failed = expired_probe->size;
		sctp_plpmtud_search_delete_probes(&(net->plpmtud_probes), expired_probe->size, false, true, true);
	}

	/* try to send a new probe packet */
	probe_size = net->plpmtud_get_next_candidate(stcb, net, false);
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
	if (ptb_mtu < sctp_plpmtud_get_pmtu(net)) {
		/* reported MTU is smaller than a previously successful probed size. Go back to BASE. */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_5);
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_BASE);
	} else if (ptb_mtu == sctp_plpmtud_get_pmtu(net)) {
		/* reported MTU confirmed current PMTU. Transition to SEARCH_COMPLETE */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_6);
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCHCOMPLETE);
	} else if (!sctp_plpmtud_search_exists_larger_probe(&(net->plpmtud_probes), ptb_mtu)) {
		/* no probe sent that would trigger this PTB, ignore. */
	} else {
		/* PMTU < PTB_MTU < MAX_PMTU */
		/* use reported MTU for a new probe */
		net->plpmtud_last_probe_acked = false;
		net->plpmtud_max_pmtu = ptb_mtu;
		sctp_plpmtud_search_delete_probes(&(net->plpmtud_probes), ptb_mtu, false, false, true);
		if (!sctp_plpmtud_exists_probe(&(net->plpmtud_probes), ptb_mtu)) {
			sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_7);
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
	sctp_plpmtud_search_delete_probes(&(net->plpmtud_probes), 0, true, true, true);
}

static void
sctp_plpmtud_searchcomplete_begin(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE begin\n");

	/* write discovered PMTU into the host cache (FreeBSD) or set it for the route */
	sctp_plpmtud_cache_pmtu(stcb, net, sctp_plpmtud_get_pmtu(net), true);

	/* schedule raise timer */
	net->plpmtud_last_probe = NULL;
	net->plpmtud_timer_value = net->plpmtud_raise_time;
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net);
}

static void
sctp_plpmtud_searchcomplete_on_probe_acked(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t acked_probe_size)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE %u acked\n", acked_probe_size);
	if (acked_probe_size <= sctp_plpmtud_get_pmtu(net)) {
		/* ignore ack */
		return;
	}

	/* PMTU increased */
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_9);
	sctp_plpmtud_set_pmtu(stcb, net, acked_probe_size, false);

	net->plpmtud_max_pmtu = sctp_plpmtud_get_upper_limit(net);
	if (sctp_plpmtud_get_pmtu(net) < net->plpmtud_max_pmtu) {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCH);
	} else {
		/* can't further increase current PMTU, maybe later, schedule raise timer */
		net->plpmtud_last_probe = NULL;
		net->plpmtud_timer_value = net->plpmtud_raise_time;
		sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net);
	}
}

static void
sctp_plpmtud_searchcomplete_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net, struct sctp_plpmtud_probe *expired_probe)
{
	struct sctp_plpmtud_probe *probe;

	if (expired_probe == NULL) {
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE raise timer fired\n");
		net->plpmtud_max_pmtu = sctp_plpmtud_get_upper_limit(net);
		if (sctp_plpmtud_get_pmtu(net) < net->plpmtud_max_pmtu) {
			probe = sctp_plpmtud_add_probe(&(net->plpmtud_probes), min(sctp_plpmtud_get_pmtu(net) + SCTP_PLPMTUD_STEPSIZE, net->plpmtud_max_pmtu), &(stcb->sctp_ep->sctp_ep));
			sctp_plpmtud_send_probe(stcb, net, probe, false);
		} else {
			/* can't increase current PMTU, maybe later, reschedule raise timer */
			net->plpmtud_last_probe = NULL;
			net->plpmtud_timer_value = net->plpmtud_raise_time;
			sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net);
		}
	} else {
		/* raise probe expired */
		SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE %u expired\n", expired_probe->size);
		if (expired_probe->count < net->plpmtud_max_probes) {
			sctp_plpmtud_send_probe(stcb, net, expired_probe, false);
		} else {
			/* give up, reschedule raise timer */
			sctp_plpmtud_delete_probe(&(net->plpmtud_probes), expired_probe);
			net->plpmtud_last_probe = NULL;
			net->plpmtud_timer_value = net->plpmtud_raise_time;
			sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net);
		}
	}
}

static void
sctp_plpmtud_searchcomplete_on_ptb_received(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t ptb_mtu)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE PTB received reporting an MTU of %u\n", ptb_mtu);
	/* correct ptb_mtu to the next smaller multiple of 4 */
	ptb_mtu = (ptb_mtu >> 2) << 2;
	if (ptb_mtu < sctp_plpmtud_get_pmtu(net)) {
		/* reported MTU is smaller than the current PMTU. Go back to BASE. */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_10);
		sctp_plpmtud_cache_pmtu(stcb, net, ptb_mtu, false);
		net->plpmtud_max_pmtu = ptb_mtu;
		sctp_plpmtud_set_pmtu(stcb, net, ptb_mtu, true);
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_BASE);
	} else if (ptb_mtu == sctp_plpmtud_get_pmtu(net)) {
		/* reported MTU confirmed the current PMTU. Reschedule RAISE_TIMER */
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_11);
		net->plpmtud_last_probe = NULL;
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
	uint32_t lower_limit, upper_limit;

	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: SEARCH_COMPLETE PMTU reported invalid with largest_acked_since_loss=%u\n", largest_acked_since_loss);

	upper_limit = sctp_plpmtud_get_upper_limit(net);
	lower_limit = sctp_plpmtud_get_lower_limit(stcb, net, upper_limit);
	net->plpmtud_max_pmtu = sctp_plpmtud_find_smaller_max(stcb, net, lower_limit, min(sctp_plpmtud_get_pmtu(net), upper_limit));
	if (largest_acked_since_loss >= sctp_plpmtud_get_base(stcb, net, lower_limit, net->plpmtud_max_pmtu)) {
		sctp_plpmtud_set_pmtu(stcb, net, largest_acked_since_loss, false);
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_SEARCH);
	} else {
		sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_BASE);
	}
}

static void
sctp_plpmtud_disabled_begin(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: DISABLED begin\n");

	/* cleanup probes list */
	sctp_plpmtud_search_delete_probes(&(net->plpmtud_probes), 0, true, true, true);
	if (SCTP_OS_TIMER_PENDING(&net->pmtu_timer.timer)) {
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net, SCTP_FROM_SCTP_PLPMTUD + SCTP_LOC_12);
	}
}

static void
sctp_plpmtud_disabled_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net, struct sctp_plpmtud_probe *expired_probe)
{
	/* used for delayed start */
	sctp_plpmtud_start(stcb, net);
}

void
sctp_plpmtud_start(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	SCTPDBG(SCTP_DEBUG_UTIL1, "PLPMTUD: start\n");

	/* init variables */
	net->plpmtud_min_pmtu = 0;
	net->plpmtud_max_pmtu = SCTP_PLPMTUD_MAX_IP_SIZE;
	net->plpmtud_timer_value = 0;
	net->plpmtud_last_probe = NULL;
	net->plpmtud_state = SCTP_PLPMTUD_STATE_DISABLED;
	TAILQ_INIT(&(net->plpmtud_probes));

	sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_BASE);
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
	net->plpmtud_state = SCTP_PLPMTUD_STATE_DISABLED;
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep, stcb, net);
}

static void
sctp_plpmtud_begin(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_BASE:
		sctp_plpmtud_base_begin(stcb, net);
		return;
	case SCTP_PLPMTUD_STATE_ERROR:
		sctp_plpmtud_error_begin(stcb, net);
		return;
	case SCTP_PLPMTUD_STATE_SEARCH:
		sctp_plpmtud_search_begin(stcb, net);
		return;
	case SCTP_PLPMTUD_STATE_SEARCHCOMPLETE:
		sctp_plpmtud_searchcomplete_begin(stcb, net);
		return;
	case SCTP_PLPMTUD_STATE_DISABLED:
		sctp_plpmtud_disabled_begin(stcb, net);
		return;
	}
}

void
sctp_plpmtud_on_probe_acked(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t probe_id)
{
	struct sctp_plpmtud_probe *acked_probe;
	uint32_t acked_probe_size;

	acked_probe = sctp_plpmtud_get_probe(&(net->plpmtud_probes), probe_id);
	if (acked_probe == NULL) {
		/* could not find a probe with the given ID -> do nothing */
		return;
	}
	acked_probe_size = acked_probe->size;
	sctp_plpmtud_delete_probe(&(net->plpmtud_probes), acked_probe);

	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_BASE:
		sctp_plpmtud_base_on_probe_acked(stcb, net, acked_probe_size);
		return;
	case SCTP_PLPMTUD_STATE_ERROR:
		sctp_plpmtud_error_on_probe_acked(stcb, net, acked_probe_size);
		return;
	case SCTP_PLPMTUD_STATE_SEARCH:
		sctp_plpmtud_search_on_probe_acked(stcb, net, acked_probe_size);
		return;
	case SCTP_PLPMTUD_STATE_SEARCHCOMPLETE:
		sctp_plpmtud_searchcomplete_on_probe_acked(stcb, net, acked_probe_size);
		return;
	}
}

void
sctp_plpmtud_on_probe_timeout(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	struct sctp_plpmtud_probe *expired_probe;

	expired_probe = net->plpmtud_last_probe;
	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_BASE:
		sctp_plpmtud_base_on_probe_timeout(stcb, net, expired_probe);
		return;
	case SCTP_PLPMTUD_STATE_ERROR:
		sctp_plpmtud_error_on_probe_timeout(stcb, net, expired_probe);
		return;
	case SCTP_PLPMTUD_STATE_SEARCH:
		sctp_plpmtud_search_on_probe_timeout(stcb, net, expired_probe);
		return;
	case SCTP_PLPMTUD_STATE_SEARCHCOMPLETE:
		sctp_plpmtud_searchcomplete_on_probe_timeout(stcb, net, expired_probe);
		return;
	case SCTP_PLPMTUD_STATE_DISABLED:
		sctp_plpmtud_disabled_on_probe_timeout(stcb, net, expired_probe);
		return;
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
		sctp_plpmtud_base_on_ptb_received(stcb, net, ptb_mtu);
		return;
	case SCTP_PLPMTUD_STATE_SEARCH:
		sctp_plpmtud_search_on_ptb_received(stcb, net, ptb_mtu);
		return;
	case SCTP_PLPMTUD_STATE_SEARCHCOMPLETE:
		sctp_plpmtud_searchcomplete_on_ptb_received(stcb, net, ptb_mtu);
		return;
	}
}

void
sctp_plpmtud_on_pmtu_invalid(struct sctp_tcb *stcb, struct sctp_nets *net, uint32_t largest_sctp_packet_acked_since_loss)
{
	uint32_t largest_acked_since_loss;

	largest_acked_since_loss = largest_sctp_packet_acked_since_loss + sctp_plpmtud_get_overhead(net);
	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_SEARCH:
		sctp_plpmtud_search_on_pmtu_invalid(stcb, net, largest_acked_since_loss);
		return;
	case SCTP_PLPMTUD_STATE_SEARCHCOMPLETE:
		sctp_plpmtud_searchcomplete_on_pmtu_invalid(stcb, net, largest_acked_since_loss);
		return;
	}
}

static void
sctp_plpmtud_end(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	switch (net->plpmtud_state) {
	case SCTP_PLPMTUD_STATE_SEARCH:
		sctp_plpmtud_search_end(stcb, net);
		return;
	}
}

void
sctp_plpmtud_stop(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	sctp_plpmtud_newstate(stcb, net, SCTP_PLPMTUD_STATE_DISABLED);
}

static void
sctp_plpmtud_newstate(struct sctp_tcb *stcb, struct sctp_nets *net, uint8_t newstate)
{
	sctp_plpmtud_end(stcb, net);
	net->plpmtud_state = newstate;
	sctp_plpmtud_begin(stcb, net);
}
