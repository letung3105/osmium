// Disable std library because its depends on OS functionalities (threads, files, networking, etc.)
// The eh_personality language item marks a function that is used for implementing stack unwinding.
// By default, Rust uses unwinding to run the destructors of all live stack variables in case of
// a panic. Stack unwinding requires OS-specific libraries.
#![no_std]
// Tell the Rust compiler that we don’t want to use the normal entry point chain, `main` doesn't
// make sense without an underlying runtime that calls it.
#![no_main]

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // main() is called after the runtime is set up by the language. Because we don't have access to
    // the Rust runtime, we have to define an entrypoint. The linked find for a function named
    // `_start()` by default
    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // This function is called on panic
    loop {}
}
