use core::{
    fmt::Write,
    hint::spin_loop,
    sync::atomic::{self, AtomicPtr},
};

pub const QEMU_VIRT_UART_MMIO_ADDRESS: usize = 0x1000_0000;

/// Print out using the global UART driver.
#[macro_export]
macro_rules! print {
    ($($args:tt)+) => ({
        use core::fmt::Write;
        let mut driver = unsafe {crate::uart_ns16550::UartDriver::new(QEMU_VIRT_UART_MMIO_ADDRESS)};
        let _ = write!(driver, $($args)+);
    });
}

/// Print out with a new line using the global UART driver.
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\r\n"));
    ($fmt:expr) => ($crate::print!(concat!($fmt, "\r\n")));
    ($fmt:expr, $($args:tt)+) => ($crate::print!(concat!($fmt, "\r\n"), $($args)+));
}

/// A driver for PC16550D (Universal Asynchronous Receiver/Transmitter With FIFOs)
pub struct UartDriver {
    rbr: AtomicPtr<u8>,
    thr: AtomicPtr<u8>,
    ier: AtomicPtr<u8>,
    iir: AtomicPtr<u8>,
    fcr: AtomicPtr<u8>,
    lcr: AtomicPtr<u8>,
    mcr: AtomicPtr<u8>,
    lsr: AtomicPtr<u8>,
    msr: AtomicPtr<u8>,
    scr: AtomicPtr<u8>,
    dll: AtomicPtr<u8>,
    dlm: AtomicPtr<u8>,
}

impl Write for UartDriver {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        s.bytes().for_each(|b| self.put(b));
        Ok(())
    }
}

impl UartDriver {
    pub unsafe fn new(base_address: usize) -> Self {
        let base_ptr = base_address as *mut u8;
        Self {
            rbr: AtomicPtr::new(base_ptr.add(0)),
            thr: AtomicPtr::new(base_ptr.add(0)),
            ier: AtomicPtr::new(base_ptr.add(1)),
            iir: AtomicPtr::new(base_ptr.add(2)),
            fcr: AtomicPtr::new(base_ptr.add(2)),
            lcr: AtomicPtr::new(base_ptr.add(3)),
            mcr: AtomicPtr::new(base_ptr.add(4)),
            lsr: AtomicPtr::new(base_ptr.add(5)),
            msr: AtomicPtr::new(base_ptr.add(6)),
            scr: AtomicPtr::new(base_ptr.add(7)),
            dll: AtomicPtr::new(base_ptr.add(0)),
            dlm: AtomicPtr::new(base_ptr.add(1)),
        }
    }

    pub fn initialize(&mut self) {
        let ier = self.ier.load(atomic::Ordering::Relaxed);
        let fcr = self.fcr.load(atomic::Ordering::Relaxed);
        let lcr = self.lcr.load(atomic::Ordering::Relaxed);
        let mcr = self.mcr.load(atomic::Ordering::Relaxed);
        let dll = self.dll.load(atomic::Ordering::Relaxed);
        let dlm = self.dlm.load(atomic::Ordering::Relaxed);
        unsafe {
            // Enable FIFO, clear TX/RX queues, and set interrupt watermark at 14 bytes
            fcr.write(1 << 0 | 1 << 1 | 1 << 2 | 1 << 6 | 1 << 7);
            // Set data word length to 8 bits
            lcr.write(1 << 0 | 1 << 1);
            // Enable receiver buffer interrupts
            ier.write(1 << 0);

            // Enable DLAB
            let lcr_bak = lcr.read();
            lcr.write(lcr_bak | 1 << 7);
            // Set the divisor from a global clock rate of 22.729 MHz (22,729,000 cycles per second) to a signaling rate
            // of 2400 (BAUD). The formula given in the NS16500A specification for calculating the divisor is:
            // divisor = ceil((clock_hz) / (baud_sps x 16))
            // divisor = ceil(22_729_000 / (2400 x 16))
            // divisor = ceil(22_729_000 / 38_400)
            // divisor = ceil(591.901)
            // divisor = 592
            let divisor = 592u16;
            let divisor_ls = divisor & 0xff;
            let divisor_ms = divisor >> 8;
            // Set divisor least significant bits
            dll.write(divisor_ls as u8);
            // Set divisor most significant bits
            dlm.write(divisor_ms as u8);
            // Disable DLAB
            lcr.write(lcr_bak);

            // Mark data terminal ready, and signal request to send
            mcr.write(1 << 0 | 1 << 1);
        }
    }

    /// Write a byte into the Transmitter Holding Register (THR)
    pub fn put(&mut self, byte: u8) {
        let thr = self.thr.load(atomic::Ordering::Relaxed);
        let lsr = self.lsr.load(atomic::Ordering::Relaxed);
        unsafe {
            while lsr.read() & (1 << 6) == 0 {
                spin_loop();
            }
            thr.write(byte);
        }
    }

    /// Read the next available byte from the Receiver Buffer Register (RBR)
    pub fn get(&mut self) -> u8 {
        let rbr = self.rbr.load(atomic::Ordering::Relaxed);
        let lsr = self.lsr.load(atomic::Ordering::Relaxed);
        unsafe {
            while lsr.read() & (1 << 0) == 0 {
                spin_loop();
            }
            rbr.read()
        }
    }
}