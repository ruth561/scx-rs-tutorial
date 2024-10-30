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
    // スケルトンファイルで定義されているBpfSkelBuilderを用いてスケジューラの
    // ロード処理を行っていく。
    let skel_builder = BpfSkelBuilder::default();

    // libbpfのときと同じで open -> load -> attach の順番に処理を行っていく
    // それぞれの引数で `tutorial_ops` を指定しているが、これはsrc/bpf/main.bpf.cにて
    // SCX_OPS_DEFINEマクロを用いて定義したスケジューラの名前をここに指定する。
    let mut open_object = MaybeUninit::uninit();
    let mut skel = scx_ops_open!(skel_builder, &mut open_object, tutorial_ops).unwrap();
    let mut skel = scx_ops_load!(skel, tutorial_ops, uei).unwrap();
    let _link = scx_ops_attach!(skel, tutorial_ops).unwrap();

    println!("[*] BPF scheduler starting!");


    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
