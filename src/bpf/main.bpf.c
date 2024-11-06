// SPDX-License-Identifier: GPL-2.0

#include "intf.h"
#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
char _license[] SEC("license") = "GPL";
#define SHARED_DSQ 0

/**
 * stats - BPF map for counting callback invocations
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, TUTORIAL_NR_STATS);
} stats SEC(".maps");

void stat_inc(u32 idx)
{
	u64 *cnt;
	
	cnt = bpf_map_lookup_elem(&stats, &idx);
	if (cnt)
		*cnt += 1;
	else
		bpf_printk("[ WARN ] failed to lookup elem from stats. idx = %u\n", idx);
}

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS_SLEEPABLE(tutorial_init)
{
	stat_inc(TUTORIAL_STAT_INIT);

	bpf_printk("[*] tutorial_init");
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(tutorial_exit, struct scx_exit_info *ei)
{
	stat_inc(TUTORIAL_STAT_EXIT);

	bpf_printk("[*] tutorial_exit");
	UEI_RECORD(uei, ei);
}

s32 BPF_STRUCT_OPS(tutorial_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	stat_inc(TUTORIAL_STAT_INIT_TASK);

	bpf_printk("[ init_task ] pid=%d, fork=%d, comm=%s",
		p->pid, args->fork, p->comm);
	return 0;
}

void BPF_STRUCT_OPS(tutorial_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	stat_inc(TUTORIAL_STAT_EXIT_TASK);

	bpf_printk("[ exit_task ] pid=%d, canceled=%d",
		p->pid, args->cancelled);
}

SCX_OPS_DEFINE(tutorial_ops,
	.init		= (void *)tutorial_init,
	.exit		= (void *)tutorial_exit,
	.init_task	= (void *)tutorial_init_task,
	.exit_task	= (void *)tutorial_exit_task,
	.name		= "tutorial");
