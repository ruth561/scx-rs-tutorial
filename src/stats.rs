// SPDX-License-Identifier: GPL-2.0

#![allow(non_upper_case_globals)]

use crate::BpfSkel;
use crate::bpf_intf::*;

use libbpf_rs::MapCore;

fn idx_to_name(stat_idx: u32) -> &'static str
{
	match stat_idx {
		stat_idx_TUTORIAL_STAT_INIT => "init",
		stat_idx_TUTORIAL_STAT_EXIT => "exit",
		stat_idx_TUTORIAL_STAT_INIT_TASK => "init_task",
		stat_idx_TUTORIAL_STAT_EXIT_TASK => "exit_task",
		stat_idx_TUTORIAL_STAT_ENABLE => "enable",
		stat_idx_TUTORIAL_STAT_DISABLE => "disable",
		stat_idx_TUTORIAL_STAT_RUNNABLE => "runnable",
		stat_idx_TUTORIAL_STAT_RUNNING => "running",
		stat_idx_TUTORIAL_STAT_STOPPING => "stopping",
		stat_idx_TUTORIAL_STAT_QUIESCENT => "quiescent",
		stat_idx_TUTORIAL_STAT_SELECT_CPU => "select_cpu",
		stat_idx_TUTORIAL_STAT_ENQUEUE => "enqueue",
		stat_idx_TUTORIAL_STAT_DEQUEUE => "dequeue",
		stat_idx_TUTORIAL_STAT_DISPATCH => "dispatch",
		_ => "[ unknown ]",
	}
}

fn print_header(nr_cpus: u32)
{
	print!("| {:10} |", " ");
	for cpu in 0..nr_cpus {
		print!(" {:^5} |", cpu);
	}
	println!(" {:>5} |", "sum");
	for _ in 0..(14 + 8 * (nr_cpus + 1)) {
		print!("=");
	}
	println!("");
}

pub fn report_stats(skel: &BpfSkel)
{
	let stats_map = &skel.maps.stats;

	print_header(12); // hardcoding
	for stat_idx in 0..stat_idx_TUTORIAL_NR_STATS {
		/*
		 * Convert stat_idx into a byte array since the map requires the
		 * key in byte format.
		 */
		let key = stat_idx.to_ne_bytes();
		/*
		 * cpu_stat_vec is a two-dimensional array where the first dimension
		 * represents CPUs and the second dimension contains the byte
		 * representation of values.
		 */
		let cpu_stat_vec = stats_map
			.lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
			.unwrap()
			.unwrap();
		
		/*
		 * Print each row of the stats entries. For example:
		 * |       init |     0 |     0 |     0 |     0 |     1 |
		 * |       exit |     0 |     0 |     0 |     0 |     0 |
		 * |  init_task |     0 |     2 |     2 |     2 |  1670 |
		 * |  exit_task |     0 |     1 |     1 |     3 |    15 |
		 */
		print!("| {:>10} |", idx_to_name(stat_idx));
		let mut sum = 0;
		for data in cpu_stat_vec {
			let cnt = u64::from_ne_bytes(data.as_slice().try_into().unwrap());
			print!(" {:>5} |", cnt);
			sum += cnt;
		}
		println!(" {:>5} |", sum);
	}
	println!("");
}
