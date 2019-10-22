/*
 * Fair Queue
 *
 *  Copyright (C) 2013-2015 Eric Dumazet <edumazet@google.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>

#include "utils.h"
#include "tc_util.h"
#include "cn_opts.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... cn [ limit PACKETS ] [ flow_limit PACKETS ]\n");
	fprintf(stderr, "              [ quantum BYTES ] [ initial_quantum BYTES ]\n");
	fprintf(stderr, "              [ maxrate RATE  ] [ buckets NUMBER ]\n");
	fprintf(stderr, "              [ [no]pacing ] [ refill_delay TIME ]\n");
	fprintf(stderr, "              [ low_rate_threshold RATE ]\n");
	fprintf(stderr, "              [ orphan_mask MASK]\n");
	fprintf(stderr, "              [ ce_threshold TIME ]\n");
	fprintf(stderr, "              [ guard_interval POSITIVE_REAL_NUMBER ]\n");
	fprintf(stderr, "              [ max_increase POSITIVE_REAL_NUMBER ]\n");
	fprintf(stderr, "              [ max_monitoring_interval SECONDS ]\n");
}

static unsigned int ilog2(unsigned int val)
{
	unsigned int res = 0;

	val--;
	while (val) {
		res++;
		val >>= 1;
	}
	return res;
}

static int cn_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			struct nlmsghdr *n, const char *dev)
{
	unsigned int plimit;
	unsigned int flow_plimit;
	unsigned int quantum;
	unsigned int initial_quantum;
	unsigned int buckets = 0;
	unsigned int maxrate;
	unsigned int low_rate_threshold;
	unsigned int defrate;
	unsigned int refill_delay;
	unsigned int orphan_mask;
	unsigned int ce_threshold;
	double guard_interval;
	double max_increase;
	double max_monitoring_interval;

	bool set_plimit = false;
	bool set_flow_plimit = false;
	bool set_quantum = false;
	bool set_initial_quantum = false;
	bool set_maxrate = false;
	bool set_defrate = false;
	bool set_refill_delay = false;
	bool set_orphan_mask = false;
	bool set_low_rate_threshold = false;
	bool set_ce_threshold = false;
	bool set_guard_interval = false;
	bool set_max_increase = false;
	bool set_max_monitoring_interval = false;
	int pacing = -1;
	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_unsigned(&plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
			set_plimit = true;
		} else if (strcmp(*argv, "flow_limit") == 0) {
			NEXT_ARG();
			if (get_unsigned(&flow_plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"flow_limit\"\n");
				return -1;
			}
			set_flow_plimit = true;
		} else if (strcmp(*argv, "buckets") == 0) {
			NEXT_ARG();
			if (get_unsigned(&buckets, *argv, 0)) {
				fprintf(stderr, "Illegal \"buckets\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "maxrate") == 0) {
			NEXT_ARG();
			if (strchr(*argv, '%')) {
				if (get_percent_rate(&maxrate, *argv, dev)) {
					fprintf(stderr, "Illegal \"maxrate\"\n");
					return -1;
				}
			} else if (get_rate(&maxrate, *argv)) {
				fprintf(stderr, "Illegal \"maxrate\"\n");
				return -1;
			}
			set_maxrate = true;
		} else if (strcmp(*argv, "low_rate_threshold") == 0) {
			NEXT_ARG();
			if (get_rate(&low_rate_threshold, *argv)) {
				fprintf(stderr, "Illegal \"low_rate_threshold\"\n");
				return -1;
			}
			set_low_rate_threshold = true;
		} else if (strcmp(*argv, "ce_threshold") == 0) {
			NEXT_ARG();
			if (get_time(&ce_threshold, *argv)) {
				fprintf(stderr, "Illegal \"ce_threshold\"\n");
				return -1;
			}
			set_ce_threshold = true;
		} else if (strcmp(*argv, "defrate") == 0) {
			NEXT_ARG();
			if (strchr(*argv, '%')) {
				if (get_percent_rate(&defrate, *argv, dev)) {
					fprintf(stderr, "Illegal \"defrate\"\n");
					return -1;
				}
			} else if (get_rate(&defrate, *argv)) {
				fprintf(stderr, "Illegal \"defrate\"\n");
				return -1;
			}
			set_defrate = true;
		} else if (strcmp(*argv, "quantum") == 0) {
			NEXT_ARG();
			if (get_unsigned(&quantum, *argv, 0)) {
				fprintf(stderr, "Illegal \"quantum\"\n");
				return -1;
			}
			set_quantum = true;
		} else if (strcmp(*argv, "initial_quantum") == 0) {
			NEXT_ARG();
			if (get_unsigned(&initial_quantum, *argv, 0)) {
				fprintf(stderr, "Illegal \"initial_quantum\"\n");
				return -1;
			}
			set_initial_quantum = true;
		} else if (strcmp(*argv, "orphan_mask") == 0) {
			NEXT_ARG();
			if (get_unsigned(&orphan_mask, *argv, 0)) {
				fprintf(stderr, "Illegal \"initial_quantum\"\n");
				return -1;
			}
			set_orphan_mask = true;
		} else if (strcmp(*argv, "refill_delay") == 0) {
			NEXT_ARG();
			if (get_time(&refill_delay, *argv)) {
				fprintf(stderr, "Illegal \"refill_delay\"\n");
				return -1;
			}
			set_refill_delay = true;
		} else if (strcmp(*argv, "guard_interval") == 0) {
			NEXT_ARG();
			char *ptr;
			guard_interval = strtod(*argv, &ptr);
			if (guard_interval <= 0.0) {
				fprintf(stderr, "Illegal \"guard_interval\"\n");
				return -1;
			}
			set_guard_interval = true;
		} else if (strcmp(*argv, "max_increase") == 0) {
			NEXT_ARG();
			char *ptr;
			max_increase = strtod(*argv, &ptr);
			if (max_increase <= 0.0) {
				fprintf(stderr, "Illegal \"max_increase\"\n");
				return -1;
			}
			set_max_increase = true;
		} else if (strcmp(*argv, "max_monitoring_interval") == 0) {
			NEXT_ARG();
			char *ptr;
			max_monitoring_interval = strtod(*argv, &ptr);
			if (max_monitoring_interval <= 0.0) {
				fprintf(stderr, "Illegal \"max_monitoring_interval\"\n");
				return -1;
			}
			set_max_monitoring_interval = true;
		} else if (strcmp(*argv, "pacing") == 0) {
			pacing = 1;
		} else if (strcmp(*argv, "nopacing") == 0) {
			pacing = 0;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	tail = addattr_nest(n, 1024, TCA_OPTIONS);
	if (buckets) {
		unsigned int log = ilog2(buckets);

		addattr_l(n, 1024, TCA_CN_BUCKETS_LOG,
			  &log, sizeof(log));
	}
	if (set_plimit)
		addattr_l(n, 1024, TCA_CN_PLIMIT,
			  &plimit, sizeof(plimit));
	if (set_flow_plimit)
		addattr_l(n, 1024, TCA_CN_FLOW_PLIMIT,
			  &flow_plimit, sizeof(flow_plimit));
	if (set_quantum)
		addattr_l(n, 1024, TCA_CN_QUANTUM, &quantum, sizeof(quantum));
	if (set_initial_quantum)
		addattr_l(n, 1024, TCA_CN_INITIAL_QUANTUM,
			  &initial_quantum, sizeof(initial_quantum));
	if (pacing != -1)
		addattr_l(n, 1024, TCA_CN_RATE_ENABLE,
			  &pacing, sizeof(pacing));
	if (set_maxrate)
		addattr_l(n, 1024, TCA_CN_FLOW_MAX_RATE,
			  &maxrate, sizeof(maxrate));
	if (set_low_rate_threshold)
		addattr_l(n, 1024, TCA_CN_LOW_RATE_THRESHOLD,
			  &low_rate_threshold, sizeof(low_rate_threshold));
	if (set_defrate)
		addattr_l(n, 1024, TCA_CN_FLOW_DEFAULT_RATE,
			  &defrate, sizeof(defrate));
	if (set_refill_delay)
		addattr_l(n, 1024, TCA_CN_FLOW_REFILL_DELAY,
			  &refill_delay, sizeof(refill_delay));
	if (set_orphan_mask)
		addattr_l(n, 1024, TCA_CN_ORPHAN_MASK,
			  &orphan_mask, sizeof(refill_delay));
	if (set_ce_threshold)
		addattr_l(n, 1024, TCA_CN_CE_THRESHOLD,
			  &ce_threshold, sizeof(ce_threshold));
	if (set_guard_interval) {
		fprintf(stderr, "Setting guard interval to %f\n", guard_interval);
		addattr_l(n, 1024, TCA_CN_GUARD_INTERVAL,
			  &guard_interval, sizeof(guard_interval));
	}
	if (set_max_increase) {
		fprintf(stderr, "Setting max increase to %f\n", max_increase);
		addattr_l(n, 1024, TCA_CN_MAX_INCREASE,
			  &max_increase, sizeof(max_increase));
	}
	if (set_max_monitoring_interval) {
		fprintf(stderr, "Setting max increase to %f\n", max_monitoring_interval);
		addattr_l(n, 1024, TCA_CN_MAX_MONITORING_INTERVAL,
			  &max_monitoring_interval, sizeof(max_monitoring_interval));
	}
	addattr_nest_end(n, tail);

	// fprintf(stderr, "TCA_CN_MAX in q_cn is %u\n", TCA_CN_MAX);

	return 0;
}

static int cn_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_CN_MAX + 1];
	unsigned int plimit, flow_plimit;
	unsigned int buckets_log;
	int pacing;
	unsigned int rate, quantum;
	unsigned int refill_delay;
	unsigned int orphan_mask;
	unsigned int ce_threshold;
	double guard_interval;
	double max_increase;
	double max_monitoring_interval;

	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_CN_MAX, opt);

	if (tb[TCA_CN_PLIMIT] &&
	    RTA_PAYLOAD(tb[TCA_CN_PLIMIT]) >= sizeof(__u32)) {
		plimit = rta_getattr_u32(tb[TCA_CN_PLIMIT]);
		fprintf(f, "limit %up ", plimit);
	}
	if (tb[TCA_CN_FLOW_PLIMIT] &&
	    RTA_PAYLOAD(tb[TCA_CN_FLOW_PLIMIT]) >= sizeof(__u32)) {
		flow_plimit = rta_getattr_u32(tb[TCA_CN_FLOW_PLIMIT]);
		fprintf(f, "flow_limit %up ", flow_plimit);
	}
	if (tb[TCA_CN_BUCKETS_LOG] &&
	    RTA_PAYLOAD(tb[TCA_CN_BUCKETS_LOG]) >= sizeof(__u32)) {
		buckets_log = rta_getattr_u32(tb[TCA_CN_BUCKETS_LOG]);
		fprintf(f, "buckets %u ", 1U << buckets_log);
	}
	if (tb[TCA_CN_ORPHAN_MASK] &&
	    RTA_PAYLOAD(tb[TCA_CN_ORPHAN_MASK]) >= sizeof(__u32)) {
		orphan_mask = rta_getattr_u32(tb[TCA_CN_ORPHAN_MASK]);
		fprintf(f, "orphan_mask %u ", orphan_mask);
	}
	if (tb[TCA_CN_RATE_ENABLE] &&
	    RTA_PAYLOAD(tb[TCA_CN_RATE_ENABLE]) >= sizeof(int)) {
		pacing = rta_getattr_u32(tb[TCA_CN_RATE_ENABLE]);
		if (pacing == 0)
			fprintf(f, "nopacing ");
	}
	if (tb[TCA_CN_QUANTUM] &&
	    RTA_PAYLOAD(tb[TCA_CN_QUANTUM]) >= sizeof(__u32)) {
		quantum = rta_getattr_u32(tb[TCA_CN_QUANTUM]);
		fprintf(f, "quantum %u ", quantum);
	}
	if (tb[TCA_CN_INITIAL_QUANTUM] &&
	    RTA_PAYLOAD(tb[TCA_CN_INITIAL_QUANTUM]) >= sizeof(__u32)) {
		quantum = rta_getattr_u32(tb[TCA_CN_INITIAL_QUANTUM]);
		fprintf(f, "initial_quantum %u ", quantum);
	}
	if (tb[TCA_CN_FLOW_DEFAULT_RATE] &&
	    RTA_PAYLOAD(tb[TCA_CN_FLOW_DEFAULT_RATE]) >= sizeof(__u32)) {
		rate = rta_getattr_u32(tb[TCA_CN_FLOW_DEFAULT_RATE]);

		if (rate != 0)
			fprintf(f, "defrate %s ", sprint_rate(rate, b1));
	}
	if (tb[TCA_CN_LOW_RATE_THRESHOLD] &&
	    RTA_PAYLOAD(tb[TCA_CN_LOW_RATE_THRESHOLD]) >= sizeof(__u32)) {
		rate = rta_getattr_u32(tb[TCA_CN_LOW_RATE_THRESHOLD]);

		if (rate != 0)
			fprintf(f, "low_rate_threshold %s ", sprint_rate(rate, b1));
	}
	if (tb[TCA_CN_FLOW_REFILL_DELAY] &&
	    RTA_PAYLOAD(tb[TCA_CN_FLOW_REFILL_DELAY]) >= sizeof(__u32)) {
		refill_delay = rta_getattr_u32(tb[TCA_CN_FLOW_REFILL_DELAY]);
		fprintf(f, "refill_delay %s ", sprint_time(refill_delay, b1));
	}
	if (tb[TCA_CN_CE_THRESHOLD] &&
	    RTA_PAYLOAD(tb[TCA_CN_CE_THRESHOLD]) >= sizeof(__u32)) {
		ce_threshold = rta_getattr_u32(tb[TCA_CN_CE_THRESHOLD]);
		if (ce_threshold != ~0U)
			fprintf(f, "ce_threshold %s ", sprint_time(ce_threshold, b1));
	}
	if (tb[TCA_CN_GUARD_INTERVAL] &&
	    RTA_PAYLOAD(tb[TCA_CN_GUARD_INTERVAL]) >= sizeof(__u64)) {
		uint64_t unsigned_integer = rta_getattr_u64(tb[TCA_CN_GUARD_INTERVAL]);
		guard_interval = *((double*) &unsigned_integer);
		if (guard_interval != ~0U)
			fprintf(f, "guard_interval %f ", guard_interval);
	}
	if (tb[TCA_CN_MAX_INCREASE] &&
	    RTA_PAYLOAD(tb[TCA_CN_MAX_INCREASE]) >= sizeof(__u64)) {
		uint64_t unsigned_integer = rta_getattr_u64(tb[TCA_CN_MAX_INCREASE]);
		max_increase = *((double*) &unsigned_integer);
		if (max_increase != ~0U)
			fprintf(f, "max_increase %f ", max_increase);
	}
	if (tb[TCA_CN_MAX_MONITORING_INTERVAL] &&
	    RTA_PAYLOAD(tb[TCA_CN_MAX_MONITORING_INTERVAL]) >= sizeof(__u64)) {
		uint64_t unsigned_integer = rta_getattr_u64(tb[TCA_CN_MAX_MONITORING_INTERVAL]);
		max_monitoring_interval = *((double*) &unsigned_integer);
		if (max_monitoring_interval != ~0U)
			fprintf(f, "max_monitoring_interval %f ", max_monitoring_interval);
	}

	return 0;
}

static int cn_print_xstats(struct qdisc_util *qu, FILE *f,
			   struct rtattr *xstats)
{
	struct tc_fq_qd_stats *st, _st;

	if (xstats == NULL)
		return 0;

	memset(&_st, 0, sizeof(_st));
	memcpy(&_st, RTA_DATA(xstats), min(RTA_PAYLOAD(xstats), sizeof(*st)));

	st = &_st;

	fprintf(f, "  %u flows (%u inactive, %u throttled)",
		st->flows, st->inactive_flows, st->throttled_flows);

	if (st->time_next_delayed_flow > 0)
		fprintf(f, ", next packet delay %llu ns", st->time_next_delayed_flow);

	fprintf(f, "\n  %llu gc, %llu highprio",
		st->gc_flows, st->highprio_packets);

	if (st->tcp_retrans)
		fprintf(f, ", %llu retrans", st->tcp_retrans);

	fprintf(f, ", %llu throttled", st->throttled);

	if (st->unthrottle_latency_ns)
		fprintf(f, ", %u ns latency", st->unthrottle_latency_ns);

	if (st->ce_mark)
		fprintf(f, ", %llu ce_mark", st->ce_mark);

	if (st->flows_plimit)
		fprintf(f, ", %llu flows_plimit", st->flows_plimit);

	if (st->pkts_too_long || st->allocation_errors)
		fprintf(f, "\n  %llu too long pkts, %llu alloc errors\n",
			st->pkts_too_long, st->allocation_errors);

	return 0;
}

struct qdisc_util cn_qdisc_util = {
	.id		= "cn",
	.parse_qopt	= cn_parse_opt,
	.print_qopt	= cn_print_opt,
	.print_xstats	= cn_print_xstats,
};
