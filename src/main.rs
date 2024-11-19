// SPDX-License-Identifier: GPL-2.0

mod bpf_skel;
mod bpf_intf;
mod stats;

use bpf_intf::*;
use bpf_skel::*;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Link;
use libbpf_rs::RingBufferBuilder;

use anyhow::Context;
use anyhow::Result;

use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use plain::Plain;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::rc::Rc;
use std::cell::RefCell;
use std::time::SystemTime;

unsafe impl Plain for cb_history_entry {}

const NR_CBS: usize = stat_idx_TUTORIAL_NR_STATS as usize;
const NR_CPUS: usize = 12;

fn cb_history_recorder(data: &[u8], table: &mut stats::GlobalCbTable<NR_CBS, NR_CPUS>) -> i32
{
    let entry: &cb_history_entry = plain::from_bytes(data).unwrap();
    table.record(entry.cpu, entry.cb_idx as usize);
    return 0;
}

fn main() {
    let mut stats_on = false;

    // Parse command line args
    let args: Vec<String> = std::env::args().collect();
    for arg in &args[1..] {
        match arg.as_str() {
            "--stats_on" => {
                stats_on = true;
            },
            _ => {
                println!("invalid arg: {}", arg);
                return;
            }
        }
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    }).unwrap();

    let skel_builder = BpfSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut skel = scx_ops_open!(skel_builder, &mut open_object, tutorial_ops).unwrap();
    let mut skel: BpfSkel = scx_ops_load!(skel, tutorial_ops, uei).unwrap();
    let link: Link = scx_ops_attach!(skel, tutorial_ops).unwrap();
    
    println!("[*] BPF scheduler starting!");

    skel.maps.bss_data.stats_on = stats_on;

    /*
     * Table for recording the callback history
     */
    let table = Rc::new(RefCell::new(stats::GlobalCbTable::new(stats_on)));
    let table_clone = table.clone();

    /*
     * initialize ring buffer
     */
    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.cb_history, move |data| {
        cb_history_recorder(data, &mut table_clone.borrow_mut())
    }).unwrap();
    let ringbuf = builder.build().unwrap();

    /*
     * Reports the current statistics per report_duration
     */
    let report_duration = std::time::Duration::from_secs(1);
    let mut prev = SystemTime::now();
    while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&skel, uei) {
        if stats_on {
            if ringbuf.poll(std::time::Duration::from_millis(10)).is_err() {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));

        let now = SystemTime::now();
        if prev + report_duration < now {
            if stats_on {
                println!("[*] Statistics report");
                stats::report_stats(&skel);
                table.borrow().report();
            }
            prev = now;
        }
    }

    println!("[*] BPF scheduler exiting..\n");

    /*
     * Detach the BPF scheduler and finally report the BPF maps.
     */
    link.detach().unwrap();
    uei_report!(&skel, uei).unwrap();
    if stats_on {
        println!("\n[*] Final statistics report");
        stats::report_stats(&skel);
    }
}
