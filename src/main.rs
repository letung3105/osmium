use clap::Parser;
use osmium::build;

fn main() {
    let cmd = Command::parse();
    let uefi_path = match cmd.kernel {
        Some(kernel) => build(&kernel).display().to_string(),
        None => env!("UEFI_PATH").to_string(),
    };
    let mut cmd = std::process::Command::new("qemu-system-x86_64");
    cmd.arg("-bios").arg(ovmf_prebuilt::ovmf_pure_efi());
    cmd.arg("-drive")
        .arg(format!("format=raw,file={uefi_path}"));
    let mut child = cmd.spawn().unwrap();
    child.wait().unwrap();
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Command {
    #[arg(long)]
    kernel: Option<String>,
}
