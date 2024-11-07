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
	TUTORIAL_STAT_ENABLE,
	TUTORIAL_STAT_DISABLE,
	TUTORIAL_STAT_RUNNABLE,
	TUTORIAL_STAT_RUNNING,
	TUTORIAL_STAT_STOPPING,
	TUTORIAL_STAT_QUIESCENT,
	TUTORIAL_STAT_SELECT_CPU,
	TUTORIAL_STAT_ENQUEUE,
	TUTORIAL_STAT_DEQUEUE,
	TUTORIAL_STAT_DISPATCH,
	TUTORIAL_NR_STATS,
};

#endif /* __INTF_H */
