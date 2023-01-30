use std::{env::temp_dir, path::PathBuf};

pub fn build(kernel: &str, out_dir: Option<String>) -> PathBuf {
    let kernel = PathBuf::from(kernel);
    let out_dir = out_dir
        .map(|d| PathBuf::from(d))
        .unwrap_or_else(|| temp_dir());

    // create an UEFI disk image (optional)
    let uefi_path = out_dir.join("uefi.img");
    bootloader::UefiBoot::new(&kernel)
        .create_disk_image(&uefi_path)
        .unwrap();

    return uefi_path;
}
