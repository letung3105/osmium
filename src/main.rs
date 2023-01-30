use clap::Parser;
use osmium::build;

fn main() {
    let cmd = Command::parse();
    let uefi_path = match cmd {
        Command::Build { kernel, out } => build(&kernel, out).display().to_string(),
        Command::Run { uefi } => {
            // read env variables that were set in build script
            uefi.unwrap_or(env!("UEFI_PATH").to_string())
        }
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
enum Command {
    Build {
        #[arg(long)]
        kernel: String,
        #[arg(long, short)]
        out: Option<String>,
    },
    Run {
        #[arg(long)]
        uefi: Option<String>,
    },
}
