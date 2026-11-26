//! fx — direct peer-to-peer file transfer.
//!
//! One sender, one receiver, no relay: the bytes travel over a QUIC connection
//! the two ends open directly. What the sender reads off disk is exactly what
//! the receiver writes to disk, once.

mod cache;
mod manifest;
mod progress;
mod proto;
mod recv;
mod sas;
mod send;
mod stun;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

use crate::proto::{DEFAULT_CHUNK, DEFAULT_STREAMS};

#[derive(Parser)]
#[command(
    name = "fx",
    version,
    about = "Send one file from this machine to another, directly and verifiably",
    long_about = "Send one file from this machine to another, directly and verifiably.\n\n\
        The two machines talk over a QUIC connection they open to each other: no\n\
        server holds the data, each chunk is checked against the sender's digest\n\
        before it is written, and an interrupted transfer resumes instead of\n\
        restarting."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Wait for one receiver and stream them a file
    Send {
        /// File to send
        file: PathBuf,

        /// Address to listen on; defaults to dual-stack [::]:0
        #[arg(long)]
        bind: Option<SocketAddr>,

        /// STUN server used to discover the public address
        #[arg(long, default_value = "stun.l.google.com:19302")]
        stun: String,

        /// Skip address discovery (only useful on a LAN)
        #[arg(long)]
        no_stun: bool,

        /// Bytes per verified chunk; also the resume granularity
        #[arg(long, default_value_t = DEFAULT_CHUNK)]
        chunk: u32,

        /// Upper bound on concurrent data streams
        #[arg(long, default_value_t = DEFAULT_STREAMS)]
        streams: u32,

        /// Shared secret for the receiver (random if omitted)
        #[arg(long)]
        token: Option<String>,
    },

    /// Connect to a sender and pull the file
    Recv {
        /// Comma-separated host:port candidates printed by the sender
        endpoint: String,

        /// Verify code printed by the sender
        #[arg(long)]
        code: String,

        /// Token from the sender's command line
        #[arg(long)]
        token: String,

        /// Directory to write the file into
        #[arg(short, long, default_value = ".")]
        out: PathBuf,

        /// Upper bound on concurrent data streams
        #[arg(long, default_value_t = DEFAULT_STREAMS)]
        streams: u32,

        /// Seconds to wait for the sender to answer
        #[arg(long, default_value_t = 15)]
        timeout: u64,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.cmd {
        Cmd::Send {
            file,
            bind,
            stun,
            no_stun,
            chunk,
            streams,
            token,
        } => send::run(send::SendOpts {
            file,
            bind,
            stun,
            no_stun,
            chunk_size: chunk,
            streams,
            token,
        })
        .await,
        Cmd::Recv {
            endpoint,
            code,
            token,
            out,
            streams,
            timeout,
        } => recv::run(recv::RecvOpts {
            endpoint,
            code,
            token,
            out,
            streams,
            timeout: Duration::from_secs(timeout),
        })
        .await,
    }
}
