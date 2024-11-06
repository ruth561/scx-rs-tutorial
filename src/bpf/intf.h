// SPDX-License-Identifier: GPL-2.0

/**
 * This header files contains common data structures and macros
 * used by both the BPF and application sides.
 */

#ifndef __INTF_H
#define __INTF_H

/**
 * The BPF map stats is defined in the BPF program.
 * The enum is used as the number of key in stats.
 */
enum stat_idx {
	TUTORIAL_STAT_INIT = 0,
	TUTORIAL_STAT_EXIT,
	TUTORIAL_STAT_INIT_TASK,
	TUTORIAL_STAT_EXIT_TASK,
	TUTORIAL_NR_STATS,
};

#endif /* __INTF_H */
