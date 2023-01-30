//! Test helpers

use crate::{print, println};

/// A type that executes assertions when run.
pub trait Testable {
    /// Executes the assertions.
    fn run(&self);
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        print!("{}...", core::any::type_name::<T>());
        self();
        println!("[ok]");
    }
}

/// Exit codes that we can return to QEMU
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    /// Kernel exits without error
    Success = 0x10,
    /// Kernel exits with error
    Failed = 0x11,
}

/// A custom test runner for testing the kernel.
pub fn test_runner(tests: &[&dyn Testable]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }
    // TODO: Exit QEMU
    //exit_qemu(QemuExitCode::Success);
}
