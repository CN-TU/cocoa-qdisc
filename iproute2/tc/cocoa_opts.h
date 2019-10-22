/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_COCOA_OPTS_H
#define __LINUX_COCOA_OPTS_H

// FIXME: This should include a file which defines "TCA_COCOA_MAX", but I couldn't find it.
// So this only works if you include that mysterious file before this one.

enum {
	TCA_COCOA_UNSPEC,

	TCA_COCOA_PLIMIT,		/* limit of total number of packets in queue */

	TCA_COCOA_FLOW_PLIMIT,	/* limit of packets per flow */

	TCA_COCOA_QUANTUM,		/* RR quantum */

	TCA_COCOA_INITIAL_QUANTUM,		/* RR quantum for new flow */

	TCA_COCOA_RATE_ENABLE,	/* enable/disable rate limiting */

	TCA_COCOA_FLOW_DEFAULT_RATE,/* obsolete, do not use */

	TCA_COCOA_FLOW_MAX_RATE,	/* per flow max rate */

	TCA_COCOA_BUCKETS_LOG,	/* log2(number of buckets) */

	TCA_COCOA_FLOW_REFILL_DELAY,	/* flow credit refill delay in usec */

	TCA_COCOA_ORPHAN_MASK,	/* mask applied to orphaned skb hashes */

	TCA_COCOA_LOW_RATE_THRESHOLD, /* per packet delay under this rate */

	TCA_COCOA_CE_THRESHOLD,	/* DCTCP-like CE-marking threshold */

	TCA_COCOA_GUARD_INTERVAL,

	TCA_COCOA_MAX_INCREASE,

	TCA_COCOA_MAX_MONITORING_INTERVAL,

	__TCA_COCOA_MAX,
};

#define TCA_COCOA_MAX	(__TCA_COCOA_MAX - 1)

#endif