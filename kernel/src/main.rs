// Disable std library because its depends on OS functionalities (threads, files, networking,
// etc.). Doing this causes a compilation error because of a missing language item named
// `eh_personality`, which marks a function used for handling stack unwinding. By default,
// Rust uses unwinding to run the destructors of all live stack variables in case of a panic.
// Stack unwinding requires OS-specific libraries.
#![no_std]
// Tell the Rust compiler that we don’t want to use the normal Rust-level entry point, `main`
// doesn't make sense without an underlying runtime that calls it.
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(osmium_kernel::testable::test_runner)]
#![reexport_test_harness_main = "test_main"]

use osmium_kernel::frame_buffer::FrameBufferWriter;

bootloader_api::entry_point!(kernel_main);

// main() is called after the runtime is set up by the language. Because we don't have
// access to the Rust runtime, we have to define an entrypoint.
fn kernel_main(boot_info: &'static mut bootloader_api::BootInfo) -> ! {
    if let Some(frame_buffer) = boot_info.framebuffer.as_mut() {
        let info = frame_buffer.info();
        let buffer = frame_buffer.buffer_mut();
        FrameBufferWriter::init_global(buffer, info)
    }

    #[cfg(test)]
    test_main();

    loop {}
}

// This function is called on panic
#[cfg(not(test))]
#[panic_handler]
fn handle_panic(info: &core::panic::PanicInfo) -> ! {
    use osmium_kernel::println;
    println!("{}", info);
    loop {}
}

/// Error handler for tests. Exits QEMU immediately after a panic.
#[cfg(test)]
#[panic_handler]
fn handle_panic(info: &core::panic::PanicInfo) -> ! {
    use osmium_kernel::println;
    println!("[failed]\n");
    println!("Error: {}\n", info);
    // TODO: Exit QEMU
    //exit_qemu(QemuExitCode::Failed);
    loop {}
}

#[test_case]
fn trivial_assertion() {
    assert!(1 == 1);
}
