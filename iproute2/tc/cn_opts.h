/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_CN_OPTS_H
#define __LINUX_CN_OPTS_H

// FIXME: This should include a file which defines "TCA_CN_MAX", but I couldn't find it.
// So this only works if you include that mysterious file before this one.

enum {
	TCA_CN_UNSPEC,

	TCA_CN_PLIMIT,		/* limit of total number of packets in queue */

	TCA_CN_FLOW_PLIMIT,	/* limit of packets per flow */

	TCA_CN_QUANTUM,		/* RR quantum */

	TCA_CN_INITIAL_QUANTUM,		/* RR quantum for new flow */

	TCA_CN_RATE_ENABLE,	/* enable/disable rate limiting */

	TCA_CN_FLOW_DEFAULT_RATE,/* obsolete, do not use */

	TCA_CN_FLOW_MAX_RATE,	/* per flow max rate */

	TCA_CN_BUCKETS_LOG,	/* log2(number of buckets) */

	TCA_CN_FLOW_REFILL_DELAY,	/* flow credit refill delay in usec */

	TCA_CN_ORPHAN_MASK,	/* mask applied to orphaned skb hashes */

	TCA_CN_LOW_RATE_THRESHOLD, /* per packet delay under this rate */

	TCA_CN_CE_THRESHOLD,	/* DCTCP-like CE-marking threshold */

	TCA_CN_GUARD_INTERVAL,

	TCA_CN_MAX_INCREASE,

	TCA_CN_MAX_MONITORING_INTERVAL,

	__TCA_CN_MAX,
};

#define TCA_CN_MAX	(__TCA_CN_MAX - 1)

#endif