// SPDX-License-Identifier: GPL-2.0

mod bpf_skel;
use bpf_skel::*;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;

use anyhow::Context;
use anyhow::Result;

use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;

use std::mem::MaybeUninit;

fn main() {
    let skel_builder = BpfSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut skel = scx_ops_open!(skel_builder, &mut open_object, tutorial_ops).unwrap();
    let mut skel: BpfSkel = scx_ops_load!(skel, tutorial_ops, uei).unwrap();
    let _link = scx_ops_attach!(skel, tutorial_ops).unwrap();
    
    println!("[*] BPF scheduler starting!");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
