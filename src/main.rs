// SPDX-License-Identifier: GPL-2.0

mod bpf_skel;
mod bpf_intf;
mod stats;

use bpf_skel::*;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Link;

use anyhow::Context;
use anyhow::Result;

use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn main() {
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

    while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&skel, uei) {
        std::thread::sleep(std::time::Duration::from_secs(1));

        println!("[*] Statistics report");
        stats::report_stats(&skel);
    }

    println!("[*] BPF scheduler exiting..\n");

    /*
     * Detach the BPF scheduler and finally report the BPF maps.
     */
    link.detach().unwrap();
    uei_report!(&skel, uei).unwrap();
    println!("\n[*] Final statistics report");
    stats::report_stats(&skel);
}
