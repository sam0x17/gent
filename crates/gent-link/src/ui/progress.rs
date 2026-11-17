use std::{
    io::{IsTerminal, Write},
    sync::mpsc,
    thread,
    time::Duration,
};

/// A bounded, stderr-only animation; the guard clears and joins its writer.
/// Callers scope it to work that cannot prompt or emit other terminal output.
pub(crate) struct Progress(Option<(mpsc::Sender<()>, thread::JoinHandle<()>)>);
impl Progress {
    pub fn start(label: &str) -> Self {
        if !super::human()
            || !super::terminal()
            || !std::io::stderr().is_terminal()
            || !std::io::stdout().is_terminal()
        {
            return Self(None);
        }
        let label: String = crate::display::visible(label).chars().take(64).collect();
        let color = std::env::var_os("NO_COLOR").is_none();
        let (stop, stopped) = mpsc::channel();
        let thread = thread::spawn(move || {
            if stopped.recv_timeout(Duration::from_millis(180)).is_ok() {
                return;
            }
            let frames = [
                "⡀", "⡄", "⡆", "⣆", "⣦", "⣶", "⣿", "⣾", "⣼", "⣸", "⢸", "⠸", "⠘", "⠈",
            ];
            for frame in frames.iter().cycle() {
                let mut stderr = std::io::stderr().lock();
                let _ = if color {
                    write!(stderr, "\r\x1b[2K  \x1b[36m{frame}\x1b[0m  {label}")
                } else {
                    write!(stderr, "\r\x1b[2K  {frame}  {label}")
                };
                let _ = stderr.flush();
                drop(stderr);
                if stopped.recv_timeout(Duration::from_millis(85)).is_ok() {
                    break;
                }
            }
            let mut stderr = std::io::stderr().lock();
            let _ = write!(stderr, "\r\x1b[2K");
            let _ = stderr.flush();
        });
        Self(Some((stop, thread)))
    }
}
impl Drop for Progress {
    fn drop(&mut self) {
        if let Some((stop, thread)) = self.0.take() {
            let _ = stop.send(());
            let _ = thread.join();
        }
    }
}
