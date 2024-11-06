// SPDX-License-Identifier: GPL-2.0

#include <scx/common.bpf.h>
char _license[] SEC("license") = "GPL";
#define SHARED_DSQ 0

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS_SLEEPABLE(tutorial_init)
{
	bpf_printk("[*] tutorial_init");
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(tutorial_exit, struct scx_exit_info *ei)
{
	bpf_printk("[*] tutorial_exit");
	UEI_RECORD(uei, ei);
}

s32 BPF_STRUCT_OPS(tutorial_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	bpf_printk("[ init_task ] pid=%d, fork=%d, comm=%s",
		p->pid, args->fork, p->comm);
	return 0;
}

void BPF_STRUCT_OPS(tutorial_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	bpf_printk("[ exit_task ] pid=%d, canceled=%d",
		p->pid, args->cancelled);
}

SCX_OPS_DEFINE(tutorial_ops,
	.init		= (void *)tutorial_init,
	.exit		= (void *)tutorial_exit,
	.init_task	= (void *)tutorial_init_task,
	.exit_task	= (void *)tutorial_exit_task,
	.name		= "tutorial");
