//! quarry-rs — the Quarry scanner CLI, Rust edition.
//!
//! Phase P1 surface: `parse` validates rule files against the ported DSL
//! grammar and reports structure. Scan execution lands with the DFA engine
//! (phase P2/P3). Exit codes follow upstream: 0 = no matches / clean parse,
//! 1 = matches found (scan mode), 2 = usage or load error.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("parse") if args.len() > 1 => cmd_parse(&args[1..]),
        Some("scan") if args.len() > 2 => cmd_scan(&args[1], &args[2], &args[3..]),
        Some("override") if args.len() > 1 && args[1] == "issue" => {
            cmd_override_issue(&args[2..])
        }
        Some("chain") if args.len() > 1 => cmd_chain(&args[1..]),
        Some("--version") | Some("version") => {
            println!("quarry-rs {}", env!("CARGO_PKG_VERSION"));
            println!("compiler {}", quarry_engine::COMPILER_VERSION);
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: quarry-rs parse <rule-file>...");
            eprintln!("       quarry-rs scan <rule-file> <conversation.json>");
            eprintln!("             [--surface ID] [--override-nonce HEX]");
            eprintln!("             [--override-store PATH] [--trace-chain PATH]");
            eprintln!("             [--session-id ID]");
            eprintln!("       quarry-rs override issue --rule NAME --ttl SECS");
            eprintln!("             --purpose TEXT [--store PATH]");
            eprintln!("       quarry-rs chain append <chain.jsonl> <session> <chunk>");
            eprintln!("             <trace.json> [--captured-by interposer] [--event-time NS]");
            eprintln!("       quarry-rs chain verify <chain.jsonl>");
            eprintln!("       quarry-rs version");
            eprintln!();
            eprintln!("exit codes (scan): 0 = clean, 1 = match, 2 = invalid, 3 = fail-closed");
            ExitCode::from(2)
        }
    }
}

/// Trace provenance chain (worry #5): append at the capture point, verify
/// before scanning.
fn cmd_chain(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("append") if args.len() >= 5 => {
            let chain = quarry_engine::trace_chain::TraceChain::new(&args[1]);
            let session = &args[2];
            let Ok(chunk) = args[3].parse::<u64>() else {
                eprintln!("chunk must be an integer");
                return ExitCode::from(2);
            };
            let Ok(trace_bytes) = std::fs::read(&args[4]) else {
                eprintln!("cannot read trace file {}", args[4]);
                return ExitCode::from(2);
            };
            let mut captured_by = "interposer".to_string();
            let mut event_time = None;
            let mut i = 5;
            while i < args.len() {
                match args[i].as_str() {
                    "--captured-by" if i + 1 < args.len() => {
                        captured_by = args[i + 1].clone();
                        i += 2;
                    }
                    "--event-time" if i + 1 < args.len() => {
                        event_time = args[i + 1].parse::<u128>().ok();
                        i += 2;
                    }
                    other => {
                        eprintln!("unknown or incomplete flag: {other}");
                        return ExitCode::from(2);
                    }
                }
            }
            match chain.append(session, chunk, &trace_bytes, event_time, &captured_by) {
                Ok(rec) => {
                    println!(
                        "appended: session {} chunk {} trace {} captured_by {}",
                        rec.session_id,
                        rec.chunk,
                        &rec.trace_sha512[..16],
                        rec.captured_by
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("append failed: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Some("verify") if args.len() == 2 => {
            let chain = quarry_engine::trace_chain::TraceChain::new(&args[1]);
            match chain.verify() {
                Ok(()) => {
                    println!("chain intact: {}", args[1]);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("CHAIN BROKEN: {e}");
                    ExitCode::from(2)
                }
            }
        }
        _ => {
            eprintln!("usage: quarry-rs chain append|verify ...");
            ExitCode::from(2)
        }
    }
}

/// Issue a fail-closed override nonce.
fn cmd_override_issue(args: &[String]) -> ExitCode {
    let mut rule = None;
    let mut ttl: Option<u64> = None;
    let mut purpose = None;
    let mut store = std::path::PathBuf::from("quarry-overrides.jsonl");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rule" if i + 1 < args.len() => {
                rule = Some(args[i + 1].clone());
                i += 2;
            }
            "--ttl" if i + 1 < args.len() => {
                ttl = args[i + 1].parse().ok();
                i += 2;
            }
            "--purpose" if i + 1 < args.len() => {
                purpose = Some(args[i + 1].clone());
                i += 2;
            }
            "--store" if i + 1 < args.len() => {
                store = std::path::PathBuf::from(&args[i + 1]);
                i += 2;
            }
            other => {
                eprintln!("unknown or incomplete flag: {other}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(ttl) = ttl else {
        eprintln!("--ttl SECS is required");
        return ExitCode::from(2);
    };
    let Some(purpose) = purpose else {
        eprintln!("--purpose TEXT is required (the receipt must say why)");
        return ExitCode::from(2);
    };
    let reg = quarry_engine::override_nonce::OverrideRegistry::new(&store);
    match reg.issue(rule, None, ttl, purpose) {
        Ok(rec) => {
            println!("nonce issued (single use, expires at unix {})", rec.expires);
            println!("  nonce: {}", rec.nonce);
            println!("  rule:  {}", rec.rule.as_deref().unwrap_or("<all rules>"));
            println!("  store: {}", store.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("issue failed: {e}");
            ExitCode::from(2)
        }
    }
}

/// Scan a conversation against a rule. Exit 1 on match (upstream convention),
/// 0 on clean, 2 on invalid, 3 on fail-closed (Incomplete without override).
fn cmd_scan(rule_file: &str, conv_file: &str, flags: &[String]) -> ExitCode {
    let mut surface = None;
    let mut nonce = None;
    let mut store = None;
    let mut trace_chain = None;
    let mut session_id = None;
    let mut i = 0;
    while i < flags.len() {
        match flags[i].as_str() {
            "--surface" if i + 1 < flags.len() => {
                surface = Some(flags[i + 1].clone());
                i += 2;
            }
            "--override-nonce" if i + 1 < flags.len() => {
                nonce = Some(flags[i + 1].clone());
                i += 2;
            }
            "--override-store" if i + 1 < flags.len() => {
                store = Some(std::path::PathBuf::from(&flags[i + 1]));
                i += 2;
            }
            "--trace-chain" if i + 1 < flags.len() => {
                trace_chain = Some(std::path::PathBuf::from(&flags[i + 1]));
                i += 2;
            }
            "--session-id" if i + 1 < flags.len() => {
                session_id = Some(flags[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("unknown or incomplete flag: {other}");
                return ExitCode::from(2);
            }
        }
    }
    let opts = quarry_engine::ScanOptions {
        surface,
        override_nonce: nonce,
        override_store: store,
        trace_chain: trace_chain.clone(),
        session_id: session_id.clone(),
        trace_bytes: match &trace_chain {
            Some(_) => match std::fs::read(conv_file) {
                Ok(b) => Some(b),
                Err(e) => {
                    eprintln!("cannot read conversation bytes: {e}");
                    return ExitCode::from(2);
                }
            },
            None => None,
        },
    };
    let src = match std::fs::read_to_string(rule_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read rule: {e}");
            return ExitCode::from(2);
        }
    };
    let conv = match std::fs::read_to_string(conv_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read conversation: {e}");
            return ExitCode::from(2);
        }
    };
    let conv_json: serde_json::Value = match serde_json::from_str(&conv) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("conversation JSON: {e}");
            return ExitCode::from(2);
        }
    };
    let verdict = quarry_engine::scan_source_with_options(&src, &conv_json, &opts);
    match verdict.status {
        quarry_core::ScanStatus::Complete => {
            if verdict.matched {
                println!("MATCH: {}", verdict.rule);
                ExitCode::from(1)
            } else {
                println!("clean: {}", verdict.rule);
                ExitCode::SUCCESS
            }
        }
        quarry_core::ScanStatus::Overridden { reason, nonce } => {
            // Fail-closed bypassed, receipted. The action may proceed; the
            // receipt must be mirrored into Tymelyne by the host.
            println!("OVERRIDDEN (fail-closed bypassed): {}", verdict.rule);
            println!("  nonce:   {nonce}");
            println!("  blocked on: {reason}");
            ExitCode::SUCCESS
        }
        quarry_core::ScanStatus::Incomplete(reason) => {
            eprintln!("incomplete (fail-closed): {reason}");
            ExitCode::from(3)
        }
        quarry_core::ScanStatus::Invalid(reason) => {
            eprintln!("invalid: {reason}");
            ExitCode::from(2)
        }
    }
}

fn cmd_parse(files: &[String]) -> ExitCode {
    let mut failed = false;
    for file in files {
        let src = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{}: cannot read: {e}", file);
                failed = true;
                continue;
            }
        };
        match quarry_dsl::parse_rule(&src) {
            Ok(rule) => {
                println!(
                    "{}: ok — rule \"{}\" ({} strings, {} variables, {} params)",
                    file,
                    rule.name,
                    rule.strings.len(),
                    rule.variables.len(),
                    rule.parameters.len(),
                );
            }
            Err(e) => {
                eprintln!("{file}: {e}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}
