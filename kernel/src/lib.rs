//! Kernel libaries

// Disable std library because its depends on OS functionalities (threads, files, networking,
// etc.). Doing this causes a compilation error because of a missing language item named
// `eh_personality`, which marks a function used for handling stack unwinding. By default,
// Rust uses unwinding to run the destructors of all live stack variables in case of a panic.
// Stack unwinding requires OS-specific libraries.
#![no_std]
#![deny(missing_docs)]
#![warn(
    rustdoc::all,
    clippy::all,
    rust_2018_idioms,
    rust_2021_compatibility,
    missing_debug_implementations
)]

pub mod frame_buffer;
pub mod testable;
