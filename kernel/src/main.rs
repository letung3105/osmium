// Disable std library because its depends on OS functionalities (threads, files, networking,
// etc.). Doing this causes a compilation error because of a missing language item named
// `eh_personality`, which marks a function used for handling stack unwinding. By default,
// Rust uses unwinding to run the destructors of all live stack variables in case of a panic.
// Stack unwinding requires OS-specific libraries.
#![no_std]
// Tell the Rust compiler that we don’t want to use the normal Rust-level entry point, `main`
// doesn't make sense without an underlying runtime that calls it.
#![no_main]

// This function is called on panic
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// main() is called after the runtime is set up by the language. Because we don't have
// access to the Rust runtime, we have to define an entrypoint.
fn kernel_main(_boot_info: &'static mut bootloader_api::BootInfo) -> ! {
    loop {}
}

bootloader_api::entry_point!(kernel_main);
