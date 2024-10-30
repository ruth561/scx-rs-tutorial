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

use std::fs::File;
use std::io::Read;

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


    // /sys/kernel/debug/tracing/trace_pipe から文字列を読んでstdioに出力する
    let mut file = File::open("/sys/kernel/tracing/trace_pipe").unwrap();
    let mut buffer = [0u8; 4096];

    loop {
        let n = file.read(&mut buffer).unwrap();
        if n > 0 {
            print!("{}", String::from_utf8_lossy(&buffer[..n]));
        }
    }
}
