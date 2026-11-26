//! A single-line stderr progress indicator that stays out of the way when
//! stderr is not a terminal (pipes, logs, CI).

use std::io::IsTerminal;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Print `label` and the running byte count until `bytes` reaches `total`.
/// The returned handle can simply be dropped; it stops on its own.
pub fn spawn(label: String, total: u64, bytes: Arc<AtomicU64>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let tty = std::io::stderr().is_terminal();
        if !tty {
            // Still useful in logs: one line when it finishes.
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if bytes.load(Ordering::Relaxed) >= total {
                    break;
                }
            }
            eprintln!("{label}: {}", human(total));
            return;
        }

        let started = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let done = bytes.load(Ordering::Relaxed);
            let elapsed = started.elapsed().as_secs_f64().max(0.001);
            let rate = done as f64 / elapsed;
            let pct = if total == 0 {
                100.0
            } else {
                (done as f64 / total as f64 * 100.0).min(100.0)
            };
            eprint!(
                "\r{label} {} / {}  {pct:5.1}%  {}/s   ",
                human(done),
                human(total),
                human(rate as u64)
            );
            if done >= total {
                break;
            }
        }
        eprintln!();
    })
}
