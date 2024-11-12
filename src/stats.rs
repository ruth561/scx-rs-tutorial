// SPDX-License-Identifier: GPL-2.0

#![allow(non_upper_case_globals)]

use crate::BpfSkel;
use crate::bpf_intf::*;

use libbpf_rs::MapCore;

fn idx_to_name(stat_idx: u32) -> &'static str
{
	match stat_idx {
		stat_idx_TUTORIAL_STAT_NONE => "(none)",
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
		stat_idx_TUTORIAL_STAT_CPU_ONLINE => "cpu_online",
		stat_idx_TUTORIAL_STAT_CPU_OFFLINE => "cpu_offline",
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

/******************************************************************************
 * Statistics for tracking callback transition counts
 */

/*
 * CbTable - Table for recording transitions of callback invocations
 * @NR_CBS: the number of callbacks
 * 
 * This data structure is intended to be used for managing a single table
 * instance. Its primary purpose is to handle per-CPU tables or a global
 * table representing all CPUs.
 * 
 * self.table[prev][next] represents the count of next's invocations following
 * prev's invocations.
 */
struct CbTable<const NR_CBS: usize>
{
	table: [[u64; NR_CBS]; NR_CBS],
}

impl<const NR_CBS: usize>
CbTable<NR_CBS>
{
	fn new() -> Self
	{
		CbTable {
			table: [[0; NR_CBS]; NR_CBS],
		}
	}

	fn record(&mut self, prev_cb: usize, next_cb: usize)
	{
		self.table[prev_cb][next_cb] += 1;
	}

	/*
	 * This function outputs the contents of the table in CSV format.
	 */
	#[allow(unused)]
	fn report_csv(&self)
	{
		print!(", ");
		for cb_idx in 0..NR_CBS {
			print!("{}, ", idx_to_name(cb_idx as u32));
		}
		println!("");

		for (cb_idx, row) in self.table.iter().enumerate() {
			print!("{}, ", idx_to_name(cb_idx as u32));
			for n in row {
				print!("{}, ", *n);
			}
			println!("");
		}
	}

	fn report(&self)
	{
		print!("| prev \\ next |");
		for cb_idx in 0..NR_CBS {
			print!(" {:>10.10} |", idx_to_name(cb_idx as u32));
		}
		println!("");
		for _ in 0..(15 + 13 * NR_CBS) {
			print!("=");
		}
		println!("");

		for (cb_idx, row) in self.table.iter().enumerate() {
			print!("| {:>11} |", idx_to_name(cb_idx as u32));
			for n in row {
				print!(" {:>10} |", *n);
			}
			println!("");
		}
	}

	fn get_counter(&self, prev_cb: usize, next_cb: usize) -> u64
	{
		self.table[prev_cb][next_cb]
	}

	fn add_counter(&mut self, prev_cb: usize, next_cb: usize, n: u64)
	{
		self.table[prev_cb][next_cb] += n;
	}
}

/*
 * GlobalCbTable - Manager that manages all CbTable per CPUs.
 * @NR_CBS: the number of callbacks
 * @NR_CPUS: the number of cpus
 * 
 * @prev_cb is the previously invoked callback.
 */
pub struct GlobalCbTable<const NR_CBS: usize, const NR_CPUS: usize> {
	prev_cb: [usize; NR_CPUS],
	table: [CbTable<NR_CBS>; NR_CPUS],
}

impl<const NR_CBS: usize, const NR_CPUS: usize>
GlobalCbTable<NR_CBS, NR_CPUS>
{
	pub fn new() -> Self
	{
		Self {
			prev_cb: [stat_idx_TUTORIAL_STAT_NONE as usize; NR_CPUS],
			table: std::array::from_fn(|_| CbTable::new()),
		}
	}

	pub fn record(&mut self, cpu: u32, cb: usize)
	{
		self.table[cpu as usize].record(self.prev_cb[cpu as usize], cb);
		self.prev_cb[cpu as usize] = cb;
	}

	pub fn report(&self)
	{
		let mut table = CbTable::<NR_CBS>::new();

		/*
		 * Get the summation of tables across all CPUs
		 */
		for per_cpu_table in &self.table {
			for prev_cb in 0..NR_CBS {
				for next_cb in 0..NR_CBS {
					let n = per_cpu_table.get_counter(prev_cb, next_cb);
					table.add_counter(prev_cb, next_cb, n);
				}
			}
		}
		table.report();
	}
}

impl<const NR_CBS: usize, const NR_CPUS: usize>
Drop for GlobalCbTable<NR_CBS, NR_CPUS>
{
	fn drop(&mut self) {
		self.report();
	}
}
