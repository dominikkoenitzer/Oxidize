//! The command line's stdout.
//!
//! Its reader may stop before a command is done, as `oxidize list | head -n 5`
//! does after five lines. The command then goes on with its work and what it
//! still prints is left out, so a batch uninstall still reaches every program
//! and the exit code stays the one the work earned.

use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// Set once stdout cannot be written to; nothing more is tried after that.
static CLOSED: AtomicBool = AtomicBool::new(false);

/// Write `text` to stdout and flush it. A reader that has gone ends the
/// output quietly; any other failure ends it with one warning on stderr.
pub fn write(text: fmt::Arguments<'_>) {
    write_bytes(text.to_string().as_bytes());
}

/// [`write`] for a question: whether it reached the reader, who can answer only then.
pub fn ask(text: fmt::Arguments<'_>) -> bool {
    write(text);
    !CLOSED.load(Ordering::Relaxed)
}

/// [`write`] for bytes another run printed, such as the elevated run's result.
pub fn write_bytes(bytes: &[u8]) {
    if let Some(e) = write_to(&mut io::stdout().lock(), &CLOSED, bytes) {
        crate::term::try_warn(&format!(
            "the output could not be written ({}), so the rest of it is left out",
            reason(&e)
        ));
    }
}

/// Write `bytes` to `out` and flush them, unless `closed` says an earlier
/// write failed. A failure sets `closed`, and is returned unless it says that
/// the reader has gone.
fn write_to(out: &mut impl Write, closed: &AtomicBool, bytes: &[u8]) -> Option<io::Error> {
    if closed.load(Ordering::Relaxed) {
        return None;
    }
    let e = out.write_all(bytes).and_then(|()| out.flush()).err()?;
    closed.store(true, Ordering::Relaxed);
    // Windows says 232 or 109 once the reader has gone; Rust gives both this kind.
    (e.kind() != io::ErrorKind::BrokenPipe).then_some(e)
}

/// The failure in a few plain words, without the OS error number.
fn reason(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::StorageFull => "the disk is full",
        io::ErrorKind::PermissionDenied => "access was denied",
        _ => "the output stream failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Refuses every write and flush with `error` and counts the writes.
    struct Refusing {
        error: fn() -> io::Error,
        asked: usize,
    }

    impl Refusing {
        fn new(error: fn() -> io::Error) -> Self {
            Self { error, asked: 0 }
        }
    }

    impl Write for Refusing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.asked += 1;
            Err((self.error)())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err((self.error)())
        }
    }

    /// What Windows says once the reader of a pipe has gone.
    fn closing() -> io::Error {
        io::Error::from_raw_os_error(232)
    }

    fn broken() -> io::Error {
        io::ErrorKind::BrokenPipe.into()
    }

    fn disk_full() -> io::Error {
        io::Error::from_raw_os_error(112)
    }

    #[test]
    fn a_reader_that_has_gone_ends_the_output_quietly() {
        for error in [closing as fn() -> io::Error, broken] {
            let closed = AtomicBool::new(false);
            let mut out = Refusing::new(error);
            assert!(write_to(&mut out, &closed, b"one\n").is_none());
            assert!(write_to(&mut out, &closed, b"two\n").is_none());
            assert!(closed.load(Ordering::Relaxed));
            assert_eq!(
                out.asked, 1,
                "nothing more is written once the reader has gone"
            );
        }
    }

    #[test]
    fn a_buffered_writer_meets_the_closed_pipe_when_it_flushes() {
        let closed = AtomicBool::new(false);
        let mut out = io::BufWriter::new(Refusing::new(closing));
        assert!(write_to(&mut out, &closed, b"one\n").is_none());
        assert!(closed.load(Ordering::Relaxed));
    }

    #[test]
    fn a_real_pipe_whose_reader_has_gone_ends_the_output_quietly() {
        let (reader, mut writer) = io::pipe().unwrap();
        drop(reader);
        let closed = AtomicBool::new(false);
        assert!(write_to(&mut writer, &closed, b"one\n").is_none());
        assert!(closed.load(Ordering::Relaxed));
    }

    #[test]
    fn another_failure_is_said_once_in_plain_words() {
        let closed = AtomicBool::new(false);
        let mut out = Refusing::new(disk_full);
        let e = write_to(&mut out, &closed, b"one\n").expect("said");
        assert_eq!(reason(&e), "the disk is full");
        assert!(write_to(&mut out, &closed, b"two\n").is_none());
        assert_eq!(out.asked, 1);
    }

    #[test]
    fn what_is_written_arrives_whole() {
        let closed = AtomicBool::new(false);
        let mut out = Vec::new();
        assert!(write_to(&mut out, &closed, b"3 rows\n").is_none());
        assert!(write_to(&mut out, &closed, b"Undo? ").is_none());
        assert_eq!(out, b"3 rows\nUndo? ");
        assert!(!closed.load(Ordering::Relaxed));
    }
}
