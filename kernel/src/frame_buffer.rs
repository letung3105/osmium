//! A collection for usefule data structures for interacting with the display frame buffer.

use core::{fmt, ptr};

use bootloader_api::info::{FrameBufferInfo, PixelFormat};
use noto_sans_mono_bitmap::{get_raster, RasterizedChar};
use spin::mutex::SpinMutex;

use self::font_constant::CHAR_RASTER_HEIGHT;

/// Additional vertical space between lines.
const LINE_SPACING: usize = 2;
/// Additional horizontal space between characters.
const LETTER_SPACING: usize = 0;
/// Padding from the border.
const BORDER_PADDING: usize = 2;

/// Contains constants for the system font.
mod font_constant {
    use noto_sans_mono_bitmap::{get_raster_width, FontWeight, RasterHeight};

    /// Height of each char raster. The font size is ~0.84% of this. Thus, this is the line height that
    /// enables multiple characters to be side-by-side and appear optically in one line in a natural way.
    pub const CHAR_RASTER_HEIGHT: RasterHeight = RasterHeight::Size16;

    /// The width of each single symbol of the mono space font.
    pub const CHAR_RASTER_WIDTH: usize = get_raster_width(FontWeight::Regular, CHAR_RASTER_HEIGHT);

    /// Backup character if a desired symbol is not available by the font.
    /// The '�' character requires the feature "unicode-specials".
    pub const BACKUP_CHAR: char = '�';

    /// The weight of rendered character
    pub const FONT_WEIGHT: FontWeight = FontWeight::Regular;
}

fn rasterize(c: char) -> Option<RasterizedChar> {
    get_raster(
        c,
        font_constant::FONT_WEIGHT,
        font_constant::CHAR_RASTER_HEIGHT,
    )
}

fn rasterize_lossy(c: char) -> RasterizedChar {
    rasterize(c)
        .or_else(|| rasterize(font_constant::BACKUP_CHAR))
        .expect("Should get the raster of the given char or the backup char")
}

/// The global writer instance.
pub static WRITER: spin::Once<SpinMutex<FrameBufferWriter<'static>>> = spin::Once::new();

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    use core::fmt::Write;
    if let Some(w) = WRITER.get() {
        w.lock().write_fmt(args).unwrap();
    }
}

/// Print out to the frame buffer using the global writer.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::frame_buffer::_print(format_args!($($arg)*)));
}

/// Print out with new line to the frame buffer using the global writer.
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

/// Allows writing text to a pixel-based frame buffer.
#[derive(Debug)]
pub struct FrameBufferWriter<'a> {
    buffer: &'a mut [u8],
    info: FrameBufferInfo,
    x_pos: usize,
    y_pos: usize,
}

impl<'a> FrameBufferWriter<'a> {
    /// Creates a new writer that uses the given frame buffer.
    pub fn new(buffer: &'a mut [u8], info: FrameBufferInfo) -> Self {
        let mut writer = Self {
            buffer,
            info,
            x_pos: 0,
            y_pos: 0,
        };
        writer.clear();
        writer
    }

    /// Erases all text on the screen. Resets `self.x_pos` and `self.y_pos`.
    pub fn clear(&mut self) {
        self.x_pos = BORDER_PADDING;
        self.y_pos = BORDER_PADDING;
        self.buffer.fill(0);
    }

    /// Writes a single char to the framebuffer taking care of special control characters, such as
    /// newlines and carriage returns.
    fn write_char(&mut self, c: char) {
        match c {
            '\r' => self.carriage_return(),
            '\n' => self.newline(),
            c => {
                // Move cursor by the width of the rasterized character
                let new_xpos = self.x_pos + font_constant::CHAR_RASTER_WIDTH;
                if new_xpos >= self.width() {
                    // Make a newline when we exceed the width limit
                    self.newline();
                }
                let new_ypos =
                    self.y_pos + font_constant::CHAR_RASTER_HEIGHT.val() + BORDER_PADDING;
                if new_ypos >= self.height() {
                    // Clear screen when we exceed the height limit
                    self.shift_up();
                }
                self.write_rendered_char(rasterize_lossy(c));
            }
        }
    }

    /// Prints a rendered char into the framebuffer.
    /// Updates `self.x_pos`.
    fn write_rendered_char(&mut self, rendered_char: RasterizedChar) {
        for (y, row) in rendered_char.raster().iter().enumerate() {
            for (x, byte) in row.iter().enumerate() {
                self.write_pixel(self.x_pos + x, self.y_pos + y, *byte);
            }
        }
        self.x_pos += rendered_char.width() + LETTER_SPACING;
    }

    fn write_pixel(&mut self, x: usize, y: usize, intensity: u8) {
        let pixel_offset = y * self.info.stride + x;
        let color = match self.info.pixel_format {
            PixelFormat::Rgb => [intensity, intensity, intensity / 2, 0],
            PixelFormat::Bgr => [intensity / 2, intensity, intensity, 0],
            PixelFormat::U8 => [if intensity > 200 { 0xf } else { 0 }, 0, 0, 0],
            other => {
                // set a supported (but invalid) pixel format before panicking to avoid a double
                // panic; it might not be readable though
                self.info.pixel_format = PixelFormat::Rgb;
                panic!("pixel format {:?} not supported in logger", other)
            }
        };
        let bytes_per_pixel = self.info.bytes_per_pixel;
        let byte_offset = pixel_offset * bytes_per_pixel;
        self.buffer[byte_offset..(byte_offset + bytes_per_pixel)]
            .copy_from_slice(&color[..bytes_per_pixel]);
        let _ = unsafe { ptr::read_volatile(&self.buffer[byte_offset]) };
    }

    /// Shift the screen content up by 1 line
    fn shift_up(&mut self) {
        let pixel_offset = CHAR_RASTER_HEIGHT.val() + LINE_SPACING;
        let byte_stride = self.info.stride * self.info.bytes_per_pixel;
        let head_byte_offset = pixel_offset * byte_stride;
        let tail_byte_offset = (self.info.height - pixel_offset) * byte_stride;
        self.buffer.copy_within(head_byte_offset.., 0);
        self.buffer[tail_byte_offset..].fill(0);
        self.y_pos -= pixel_offset;
    }

    fn width(&self) -> usize {
        self.info.width
    }

    fn height(&self) -> usize {
        self.info.height
    }

    fn carriage_return(&mut self) {
        self.x_pos = BORDER_PADDING;
    }

    fn newline(&mut self) {
        self.y_pos += CHAR_RASTER_HEIGHT.val() + LINE_SPACING;
        self.carriage_return();
    }
}

unsafe impl Send for FrameBufferWriter<'static> {}
unsafe impl Sync for FrameBufferWriter<'static> {}

impl<'a> fmt::Write for FrameBufferWriter<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            self.write_char(c);
        }
        Ok(())
    }
}
