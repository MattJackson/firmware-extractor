//! fwext CLI.
//!   fwext <input> [-o OUTDIR]   input -> OUTDIR/<stem>.fw.bin + .fw.json
//!   fwext <input> --print       print the JSON label only
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        eprintln!("usage: fwext <input> [-o OUTDIR] [--print]");
        std::process::exit(0);
    }
    let path = Path::new(&args[0]);
    let printonly = args.iter().any(|a| a == "--print");
    let outdir = args
        .iter()
        .position(|a| a == "-o")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| ".".to_string());

    let (fw, mut label) = fwext::extract::extract(path, None, None);
    if let Some(ref bytes) = fw {
        label.size = Some(bytes.len());
        label.sha256 = Some(fwext::sha(bytes));
    }

    if printonly || fw.is_none() {
        println!("{}", serde_json::to_string_pretty(&label).unwrap());
        std::process::exit(if fw.is_some() { 0 } else { 2 });
    }
    let fw = fw.unwrap();
    std::fs::create_dir_all(&outdir).ok();
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let fwp = format!("{}/{}.fw.bin", outdir, stem);
    std::fs::write(&fwp, &fw).unwrap();
    std::fs::write(
        format!("{}/{}.fw.json", outdir, stem),
        serde_json::to_string_pretty(&label).unwrap(),
    )
    .unwrap();
    println!(
        "{}  ({})",
        fwp,
        label.payload_form.as_deref().unwrap_or("?")
    );
}
