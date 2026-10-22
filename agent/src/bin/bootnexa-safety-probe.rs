//! BootNexa developer-only diagnostic: zero write authority.
#[cfg(windows)]
use bootnexa_agent::safety_report::collect;
#[tokio::main]
async fn main() {
    if std::env::args().len() != 2 || std::env::args().nth(1).as_deref() != Some("--probe") {
        eprintln!(
            "usage: bootnexa-safety-probe --probe (Windows only; read-only; no device selection)"
        );
        std::process::exit(2);
    }
    #[cfg(windows)]
    let result = collect().await;
    #[cfg(not(windows))]
    let result: Result<serde_json::Value, &str> =
        Err("Windows read-only probe unavailable on this operating system");
    match result {
        Ok(report) => println!(
            "{}",
            serde_json::to_string(&report).expect("report serializable")
        ),
        Err(message) => {
            // Never output raw provider errors, serials, PnP paths or secrets.
            eprintln!("{message}");
            std::process::exit(1)
        }
    }
}
