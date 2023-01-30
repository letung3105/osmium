use std::{env::temp_dir, path::PathBuf};

pub fn build(kernel: &str) -> PathBuf {
    let kernel = PathBuf::from(kernel);
    let out_dir = temp_dir();

    // create an UEFI disk image (optional)
    let uefi_path = out_dir.join("uefi.img");
    bootloader::UefiBoot::new(&kernel)
        .create_disk_image(&uefi_path)
        .unwrap();

    uefi_path
}
