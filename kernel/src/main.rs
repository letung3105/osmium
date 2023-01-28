// Disable std library because its depends on OS functionalities (threads, files, networking,
// etc.). Doing this causes a compilation error because of a missing language item named
// `eh_personality`, which marks a function used for handling stack unwinding. By default,
// Rust uses unwinding to run the destructors of all live stack variables in case of a panic.
// Stack unwinding requires OS-specific libraries.
#![no_std]
// Tell the Rust compiler that we don’t want to use the normal Rust-level entry point, `main`
// doesn't make sense without an underlying runtime that calls it.
#![no_main]

use osmium_kernel::{
    frame_buffer::{FrameBufferWriter, WRITER},
    println,
};
use spin::mutex::SpinMutex;

// This function is called on panic
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

// main() is called after the runtime is set up by the language. Because we don't have
// access to the Rust runtime, we have to define an entrypoint.
fn kernel_main(boot_info: &'static mut bootloader_api::BootInfo) -> ! {
    if let Some(frame_buffer) = boot_info.framebuffer.as_mut() {
        WRITER.call_once(|| {
            let info = frame_buffer.info();
            let buffer = frame_buffer.buffer_mut();
            SpinMutex::new(FrameBufferWriter::new(buffer, info))
        });
    }

    let mut count = 0;
    loop {
        if count % 2 == 0 {
            println!("Hello, world!");
        } else {
            println!("Goodbye, world!");
        }
        count += 1;
    }
}

bootloader_api::entry_point!(kernel_main);
