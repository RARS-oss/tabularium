//! tabularium: verifiable memory for LLM agents. CLI and MCP server entry point.

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use tabularium_core::*;
use tabularium_mcp::McpServer;

#[derive(Parser)]
#[command(name = "tabularium", version, about = "Verifiable, auditable memory for LLM agents", long_about = None)]
struct Cli {
    /// Vault directory (default: $TABULARIUM_VAULT or ~/.tabularium/default)
    #[arg(long, global = true, env = "TABULARIUM_VAULT")]
    vault: Option<PathBuf>,
    /// Personal writer identity directory (default: $TABULARIUM_IDENTITY or ~/.tabularium/identity,
    /// used only if it exists -- omit entirely to keep signing with the vault's own key alone)
    #[arg(long, global = true, env = "TABULARIUM_IDENTITY")]
    identity: Option<PathBuf>,
    /// Emit JSON instead of human-readable output
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault
    Init {
        /// Human-readable vault name
        #[arg(long, default_value = "default")]
        name: String,
        /// Project root for relative check paths (default: working directory at each open)
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Manage this machine's personal writer identity, reusable across any vault
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// Manage this vault's writer registry (who may write, and at what trust ceiling)
    Writer {
        #[command(subcommand)]
        cmd: WriterCmd,
    },
    /// Record an event (content from argument or stdin)
    Observe {
        /// utterance | action | observation | external
        #[arg(long)]
        kind: String,
        /// external | tool | agent | user (defaults by kind)
        #[arg(long)]
        trust: Option<String>,
        #[arg(long, default_value = "cli")]
        channel: String,
        content: Option<String>,
    },
    /// Derive a memory from evidence
    Remember(RememberArgs),
    /// Retrieve memories under a token budget
    Recall {
        query: Option<String>,
        #[arg(long, default_value_t = 800)]
        budget: u32,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Skip validity checks
        #[arg(long)]
        no_verify: bool,
        /// Drop stale items instead of demoting them
        #[arg(long)]
        drop_stale: bool,
    },
    /// Cheap probe for related memories. With no argument reads stdin (Claude Code hook JSON or raw text)
    Hint {
        text: Option<String>,
        #[arg(short, default_value_t = 3)]
        n: usize,
    },
    /// Run validity checks on one memory or all active ones
    Verify { memory_id: Option<String> },
    /// Find active memories with different subjects that look like the same claim (possible
    /// conflict, not a proven one — by embedding similarity, no LLM)
    Contradictions {
        /// Override vault.toml's embeddings.contradiction_threshold for this run
        #[arg(long)]
        threshold: Option<f32>,
    },
    /// Find active memories, any subjects, whose stored embeddings are near-identical --
    /// candidates to consolidate with `remember --merge` (detection only, no auto-merge)
    Duplicates {
        /// Override vault.toml's embeddings.duplicate_threshold for this run
        #[arg(long)]
        threshold: Option<f32>,
    },
    /// Tombstone a memory and redact its content
    Forget {
        memory_id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Verify the whole ledger: chain, signatures, commitments, receipts
    Audit,
    /// Apply pending events to the memory view (or rebuild it from genesis)
    Compile {
        #[arg(long)]
        rebuild: bool,
    },
    /// List ledger events
    Events {
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// List memories
    Memories {
        /// Include superseded and forgotten memories
        #[arg(long)]
        all: bool,
    },
    /// Show a signed receipt
    Receipt { id: String },
    /// Write vectors for memories that lack one (vectors live in the ledger; recall stays reproducible)
    Embed {
        /// Only report coverage, do not embed
        #[arg(long)]
        status: bool,
    },
    /// Vault status
    Info,
    /// Serve the Model Context Protocol over stdio (creates the vault if missing)
    Serve,
    /// Claude Code hook entry points; reads the hook JSON from stdin, never fails the hook
    Hook {
        /// user-prompt (UserPromptSubmit) | post-tool (PostToolUse)
        event: String,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Generate a new personal identity keypair (fails if one already exists)
    Init,
    /// Print this machine's identity public key
    Show,
}

#[derive(Subcommand)]
enum WriterCmd {
    /// Register a writer's public key with a trust ceiling
    Add {
        pubkey: String,
        /// Human-readable label
        #[arg(long)]
        name: String,
        /// external | tool | agent | user
        #[arg(long = "max-trust")]
        max_trust: String,
    },
    /// List registered writers
    List,
    /// Remove a writer from the registry
    Remove { pubkey: String },
}

#[derive(Args)]
struct RememberArgs {
    /// fact | preference | instruction | reference | note
    #[arg(long)]
    kind: String,
    /// Stable key; a newer memory with the same subject supersedes the older one
    #[arg(long)]
    subject: Option<String>,
    /// Evidence event id (repeatable)
    #[arg(long = "evidence", short = 'e')]
    evidence: Vec<String>,
    /// Id of an active memory this one consolidates (repeatable); each is superseded
    #[arg(long = "merge")]
    merge: Vec<String>,
    /// file_hash check on PATH (repeatable)
    #[arg(long = "check-file")]
    check_file: Vec<String>,
    /// file_exists check on PATH (repeatable)
    #[arg(long = "check-exists")]
    check_exists: Vec<String>,
    /// symbol_in_file check as PATH::SYMBOL (repeatable)
    #[arg(long = "check-symbol")]
    check_symbol: Vec<String>,
    /// ttl check: RFC 3339 expiry
    #[arg(long)]
    ttl: Option<String>,
    #[arg(long, default_value = "cli")]
    channel: String,
    text: Option<String>,
}

fn read_stdin() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

fn text_or_stdin(arg: Option<String>) -> Result<String> {
    match arg {
        Some(t) => Ok(t),
        None => {
            if std::io::stdin().is_terminal() {
                return Err(anyhow!("no text given and stdin is a terminal"));
            }
            Ok(read_stdin()?.trim_end().to_string())
        }
    }
}

fn open(vault_dir: &Option<PathBuf>, identity_dir: &Option<PathBuf>) -> Result<Vault> {
    let dir = Vault::resolve_dir(vault_dir.as_deref());
    let mut v = Vault::open(&dir).map_err(|e| anyhow!("{e}"))?;
    load_writer_identity(&mut v, identity_dir.as_deref())?;
    Ok(v)
}

/// Load and install this process's writer identity, if one is configured (explicit path, else
/// `TABULARIUM_IDENTITY`, else `~/.tabularium/identity` if it exists). A no-op otherwise.
fn load_writer_identity(v: &mut Vault, explicit: Option<&Path>) -> Result<()> {
    if let Some(dir) = Vault::resolve_identity_dir(explicit) {
        let keys = tabularium_core::keys::VaultKeys::load(&dir).map_err(|e| anyhow!("loading identity at {}: {e}", dir.display()))?;
        v.set_writer_identity(Some(keys));
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { name, root } => {
            let dir = Vault::resolve_dir(cli.vault.as_deref());
            let root_abs = match root {
                Some(r) => Some(clean_path(&std::fs::canonicalize(&r).with_context(|| format!("root {}", r.display()))?)),
                None => None,
            };
            let v = Vault::init(&dir, &name, root_abs.as_deref()).map_err(|e| anyhow!("{e}"))?;
            if cli.json {
                print_json(&serde_json::json!({"vault": v.dir(), "public_key": v.public_key_hex()}))?;
            } else {
                println!("vault created at {}", v.dir().display());
                println!("public key {}", v.public_key_hex());
            }
        }
        Cmd::Identity { cmd } => match cmd {
            IdentityCmd::Init => {
                let dir = Vault::resolve_identity_path(cli.identity.as_deref());
                if dir.join(tabularium_core::keys::SECRET_FILE).is_file() {
                    return Err(anyhow!("identity already exists at {} (delete it manually to regenerate)", dir.display()));
                }
                let keys = tabularium_core::keys::VaultKeys::generate().map_err(|e| anyhow!("{e}"))?;
                keys.save(&dir).map_err(|e| anyhow!("{e}"))?;
                if cli.json {
                    print_json(&serde_json::json!({"identity_dir": dir, "public_key": keys.public_key_hex()}))?;
                } else {
                    println!("identity created: {}", keys.public_key_hex());
                    println!("stored at {}", dir.display());
                }
            }
            IdentityCmd::Show => {
                let dir = Vault::resolve_identity_path(cli.identity.as_deref());
                let keys = tabularium_core::keys::VaultKeys::load(&dir)
                    .map_err(|e| anyhow!("no identity at {} (run `tabularium identity init` first): {e}", dir.display()))?;
                if cli.json {
                    print_json(&serde_json::json!({"identity_dir": dir, "public_key": keys.public_key_hex()}))?;
                } else {
                    println!("{}", keys.public_key_hex());
                }
            }
        },
        Cmd::Writer { cmd } => {
            let mut v = open(&cli.vault, &cli.identity)?;
            match cmd {
                WriterCmd::Add { pubkey, name, max_trust } => {
                    let max_trust = Trust::parse(&max_trust).ok_or_else(|| anyhow!("unknown trust '{max_trust}'"))?;
                    hex::decode(&pubkey).map_err(|_| anyhow!("pubkey must be hex"))?;
                    v.config_mut().policy.writers.insert(pubkey.clone(), WriterPolicy { name: name.clone(), max_trust });
                    v.save_config()?;
                    println!("registered writer {pubkey} as '{name}', max trust {max_trust}");
                }
                WriterCmd::List => {
                    let writers = &v.config().policy.writers;
                    if cli.json {
                        print_json(writers)?;
                    } else if writers.is_empty() {
                        println!("no registered writers (this vault's own key signs everything, unrestricted)");
                    } else {
                        for (pubkey, w) in writers {
                            println!("{pubkey} '{}' max trust {}", w.name, w.max_trust);
                        }
                    }
                }
                WriterCmd::Remove { pubkey } => {
                    if v.config_mut().policy.writers.remove(&pubkey).is_none() {
                        return Err(anyhow!("no such writer '{pubkey}'"));
                    }
                    v.save_config()?;
                    println!("removed writer {pubkey}");
                }
            }
        }
        Cmd::Observe { kind, trust, channel, content } => {
            let mut v = open(&cli.vault, &cli.identity)?;
            let kind = EventKind::parse(&kind).ok_or_else(|| anyhow!("unknown kind '{kind}'"))?;
            let trust = match trust {
                Some(t) => Some(Trust::parse(&t).ok_or_else(|| anyhow!("unknown trust '{t}'"))?),
                None => None,
            };
            let content = text_or_stdin(content)?;
            let ev = v.observe(ObserveInput { kind, content, trust, channel, meta: None })?;
            if cli.json {
                print_json(&ev)?;
            } else {
                println!("event {} seq {} kind {} trust {}", ev.id, ev.seq, ev.kind, ev.trust);
            }
        }
        Cmd::Remember(a) => {
            let mut v = open(&cli.vault, &cli.identity)?;
            let kind = MemoryKind::parse(&a.kind).ok_or_else(|| anyhow!("unknown memory kind '{}'", a.kind))?;
            let text = text_or_stdin(a.text)?;
            let mut checks = Vec::new();
            for p in a.check_file {
                checks.push(Check::FileHash { path: p, blake3: None });
            }
            for p in a.check_exists {
                checks.push(Check::FileExists { path: p });
            }
            for s in a.check_symbol {
                let (path, symbol) = s
                    .split_once("::")
                    .ok_or_else(|| anyhow!("--check-symbol expects PATH::SYMBOL, got '{s}'"))?;
                checks.push(Check::SymbolInFile { path: path.to_string(), symbol: symbol.to_string() });
            }
            if let Some(exp) = a.ttl {
                checks.push(Check::Ttl { expires: exp });
            }
            let m = v.remember(RememberInput {
                kind,
                text,
                subject: a.subject,
                evidence: a.evidence,
                checks,
                channel: a.channel,
                trust: None,
                merged_from: a.merge,
                meta: None,
            })?;
            if cli.json {
                print_json(&m)?;
            } else {
                println!("memory {} kind {} trust {} checks {} evidence {}", m.id, m.kind, m.trust, m.checks.len(), m.evidence.len());
            }
        }
        Cmd::Recall { query, budget, limit, no_verify, drop_stale } => {
            let mut v = open(&cli.vault, &cli.identity)?;
            let query = query.unwrap_or_default();
            let opts = RecallOptions { budget_tokens: budget, limit, verify: !no_verify, include_stale: !drop_stale };
            let r = v.recall(&query, &opts)?;
            if cli.json {
                print_json(&r)?;
            } else {
                println!(
                    "{} of {} matched, {} returned, {}/{} tokens, {} skipped for budget, {}, receipt {}",
                    r.matched,
                    r.considered,
                    r.items.len(),
                    r.used_tokens,
                    r.budget_tokens,
                    r.skipped_for_budget.len(),
                    r.semantic_model.as_deref().map(|m| format!("semantic via {m}")).unwrap_or_else(|| "lexical only".into()),
                    short(&r.receipt.id)
                );
                for it in &r.items {
                    let subj = it.subject.as_deref().map(|s| format!(" [{s}]")).unwrap_or_default();
                    println!("- ({}) {} {}{} :: {}", it.status, it.kind, it.trust, subj, it.text);
                    println!("    {} · {} · {}", short(&it.id), it.tokens, it.why);
                }
            }
        }
        Cmd::Hint { text, n } => {
            let v = open(&cli.vault, &cli.identity)?;
            let raw = match text {
                Some(t) => t,
                None => {
                    if std::io::stdin().is_terminal() {
                        return Err(anyhow!("no text given and stdin is a terminal"));
                    }
                    read_stdin()?
                }
            };
            // Claude Code hooks pass JSON with a "prompt" field; accept raw text too.
            let text = serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .and_then(|j| j.get("prompt").and_then(|p| p.as_str()).map(|s| s.to_string()))
                .unwrap_or(raw);
            let h = v.hint(&text, n)?;
            if cli.json {
                print_json(&h)?;
            } else if h.matched > 0 {
                let titles: Vec<String> = h.items.iter().map(|i| format!("\"{}\" ({})", i.title, short(&i.id))).collect();
                println!(
                    "Tabularium: {} related memor{} — {}. Call memory_recall to load them.",
                    h.matched,
                    if h.matched == 1 { "y" } else { "ies" },
                    titles.join("; ")
                );
            }
        }
        Cmd::Verify { memory_id } => {
            let v = open(&cli.vault, &cli.identity)?;
            let reports = v.verify(memory_id.as_deref())?;
            if cli.json {
                let items: Vec<serde_json::Value> = reports
                    .iter()
                    .map(|(m, s, c)| serde_json::json!({"memory_id": m.id, "status": s, "text": m.text, "checks": c}))
                    .collect();
                print_json(&items)?;
            } else {
                for (m, s, c) in &reports {
                    println!("({}) {} :: {}", s, short(&m.id), m.text);
                    for r in c {
                        if let CheckOutcome::Fail { reason } | CheckOutcome::Error { reason } = &r.outcome {
                            println!("    {reason}");
                        }
                    }
                }
                let stale = reports.iter().filter(|(_, s, _)| *s == Status::Stale).count();
                println!("{} checked, {} stale", reports.len(), stale);
            }
        }
        Cmd::Contradictions { threshold } => {
            let mut v = open(&cli.vault, &cli.identity)?;
            let r = v.contradictions(&ContradictOptions { threshold })?;
            if cli.json {
                print_json(&r)?;
            } else if r.model.is_none() {
                println!("no embedder available; nothing to compare");
            } else {
                for p in &r.pairs {
                    println!(
                        "cos {:.3} :: [{}] {} \"{}\"\n              vs [{}] {} \"{}\"",
                        p.cosine,
                        p.a.subject,
                        short(&p.a.id),
                        p.a.text,
                        p.b.subject,
                        short(&p.b.id),
                        p.b.text
                    );
                }
                println!("{} subject-bearing memories considered, {} possible conflict(s) at threshold {:.2}", r.considered, r.pairs.len(), r.threshold);
            }
        }
        Cmd::Duplicates { threshold } => {
            let mut v = open(&cli.vault, &cli.identity)?;
            let r = v.duplicates(&DuplicateOptions { threshold })?;
            if cli.json {
                print_json(&r)?;
            } else if r.model.is_none() {
                println!("no embedder available; nothing to compare");
            } else {
                for p in &r.pairs {
                    println!("cos {:.3} :: {} \"{}\"\n              vs {} \"{}\"", p.cosine, short(&p.a.id), p.a.text, short(&p.b.id), p.b.text);
                }
                println!(
                    "{} active memories considered, {} likely duplicate(s) at threshold {:.2} -- consolidate with `remember --merge`",
                    r.considered,
                    r.pairs.len(),
                    r.threshold
                );
            }
        }
        Cmd::Forget { memory_id, reason } => {
            let mut v = open(&cli.vault, &cli.identity)?;
            let report = v.forget(&memory_id, &reason, "cli")?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!("forgotten {} (tombstone event {})", short(&memory_id), short(&report.tombstone_event.id));
                if !report.evidence_redacted.is_empty() {
                    let ids: Vec<String> = report.evidence_redacted.iter().map(|i| short(i).to_string()).collect();
                    println!("also redacted {} evidence event(s): {}", ids.len(), ids.join(", "));
                }
            }
        }
        Cmd::Audit => {
            let v = open(&cli.vault, &cli.identity)?;
            let a = v.audit()?;
            if cli.json {
                print_json(&a)?;
            } else {
                println!(
                    "{}: {} events, {} receipts, head {}@{}",
                    if a.ok { "OK" } else { "FAILED" },
                    a.events,
                    a.receipts,
                    a.head_seq,
                    short(&a.head_hash)
                );
                for p in &a.problems {
                    println!("  ! {p}");
                }
            }
            if !a.ok {
                std::process::exit(2);
            }
        }
        Cmd::Compile { rebuild } => {
            let mut v = open(&cli.vault, &cli.identity)?;
            let r = v.compile(rebuild)?;
            if cli.json {
                print_json(&r)?;
            } else {
                println!(
                    "{} {} events (seq {}..{}), {} active / {} total memories",
                    if r.rebuilt { "rebuilt from" } else { "applied" },
                    r.applied,
                    r.from_seq + 1,
                    r.to_seq,
                    r.memories_active,
                    r.memories_total
                );
            }
        }
        Cmd::Events { after, limit } => {
            let v = open(&cli.vault, &cli.identity)?;
            let evs = v.events(after, limit)?;
            if cli.json {
                print_json(&evs)?;
            } else {
                for e in &evs {
                    let summary = match &e.payload {
                        None => "<redacted>".to_string(),
                        Some(p) => {
                            let s = p.get("content").or_else(|| p.get("text")).and_then(|x| x.as_str()).unwrap_or("");
                            s.lines().next().unwrap_or("").chars().take(70).collect()
                        }
                    };
                    println!("{:>5} {} {:<11} {:<8} {:<10} {}", e.seq, short(&e.id), e.kind.as_str(), e.trust.as_str(), e.channel, summary);
                }
            }
        }
        Cmd::Memories { all } => {
            let v = open(&cli.vault, &cli.identity)?;
            let ms = v.memories(all)?;
            if cli.json {
                print_json(&ms)?;
            } else {
                for m in &ms {
                    let state = if m.tombstoned {
                        "forgotten"
                    } else if m.superseded_by.is_some() {
                        "superseded"
                    } else {
                        "active"
                    };
                    let subj = m.subject.as_deref().map(|s| format!(" [{s}]")).unwrap_or_default();
                    println!("{} {:<11} {:<8} {:<10}{} :: {}", short(&m.id), m.kind.as_str(), m.trust.as_str(), state, subj, m.text);
                }
                println!("{} memories", ms.len());
            }
        }
        Cmd::Receipt { id } => {
            let v = open(&cli.vault, &cli.identity)?;
            let r = v.get_receipt(&id)?.ok_or_else(|| anyhow!("receipt '{id}' not found"))?;
            print_json(&r)?;
        }
        Cmd::Embed { status } => {
            let mut v = open(&cli.vault, &cli.identity)?;
            let r = if status {
                match v.embedding_model_id() {
                    Some(model) => {
                        let (covered, active) = v.embedding_coverage(&model)?;
                        EmbedReport { model: Some(model), embedded: 0, covered, active }
                    }
                    None => EmbedReport { model: None, embedded: 0, covered: 0, active: v.memories(false)?.len() },
                }
            } else {
                v.embed_missing()?
            };
            if cli.json {
                print_json(&r)?;
            } else {
                match &r.model {
                    Some(m) => println!("model {m}: {} embedded now, {}/{} active memories covered", r.embedded, r.covered, r.active),
                    None => println!("embeddings unavailable (disabled in vault.toml, TABULARIUM_NO_EMBED=1, or model failed to load); {} active memories", r.active),
                }
            }
        }
        Cmd::Info => {
            let v = open(&cli.vault, &cli.identity)?;
            let (seq, hash) = v.head()?;
            let a = v.memories(false)?.len();
            let t = v.memories(true)?.len();
            // Coverage only; do not load the model just to print info.
            let cfg_model = v.config().embeddings.model.clone();
            let enabled = v.config().embeddings.enabled;
            let stored_model = format!("fastembed:{}", cfg_model.to_ascii_lowercase());
            let (covered, _) = v.embedding_coverage(&stored_model)?;
            if cli.json {
                print_json(&serde_json::json!({
                    "vault": v.dir(), "root": v.root(), "name": v.config().name, "events": v.event_count()?,
                    "head": {"seq": seq, "hash": hash}, "memories": {"active": a, "total": t},
                    "embeddings": {"enabled": enabled, "model": cfg_model, "covered": covered, "active": a},
                    "public_key": v.public_key_hex(), "version": tabularium_core::VERSION
                }))?;
            } else {
                println!("vault     {}", v.dir().display());
                println!("root      {}", v.root().display());
                println!("events    {} (head {}@{})", v.event_count()?, seq, short(&hash));
                println!("memories  {a} active / {t} total");
                println!(
                    "vectors   {covered}/{a} under {cfg_model}{}",
                    if enabled { "" } else { " (disabled)" }
                );
                println!("pubkey    {}", v.public_key_hex());
            }
        }
        Cmd::Serve => {
            let dir = Vault::resolve_dir(cli.vault.as_deref());
            let mut vault = if Vault::exists(&dir) {
                Vault::open(&dir).map_err(|e| anyhow!("{e}"))?
            } else {
                eprintln!("[tabularium] creating vault at {}", dir.display());
                Vault::init(&dir, "default", None).map_err(|e| anyhow!("{e}"))?
            };
            load_writer_identity(&mut vault, cli.identity.as_deref())?;
            if let Some(pk) = vault.writer_public_key_hex() {
                eprintln!("[tabularium] writer identity {pk}");
            }
            eprintln!("[tabularium] serving MCP over stdio; vault {}; root {}", vault.dir().display(), vault.root().display());
            let mut server = McpServer::new(vault);
            // Long-lived process: load the model once and backfill vectors before the first recall.
            match server.vault_mut().embed_missing() {
                Ok(r) => match r.model {
                    Some(m) => eprintln!("[tabularium] embeddings via {m}: {} written, {}/{} covered", r.embedded, r.covered, r.active),
                    None => eprintln!("[tabularium] embeddings unavailable; lexical recall only"),
                },
                Err(e) => eprintln!("[tabularium] embedding backfill failed: {e}"),
            }
            server.run_stdio()?;
        }
        Cmd::Hook { event } => {
            // Hooks must never break the agent: swallow errors, exit 0, print nothing on failure.
            if let Err(e) = run_hook(&cli.vault, &cli.identity, &event) {
                eprintln!("[tabularium hook] {e}");
            }
        }
    }
    Ok(())
}

/// Strip Windows' verbatim prefix (`\\?\C:\...`) that `canonicalize` produces; keeps paths readable.
fn clean_path(p: &std::path::Path) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => p.to_path_buf(),
    }
}

fn run_hook(vault_dir: &Option<PathBuf>, identity_dir: &Option<PathBuf>, event: &str) -> Result<()> {
    // Hooks run on every prompt; never pay for a model load there.
    // SAFETY: single-threaded CLI, set before any other thread exists.
    unsafe { std::env::set_var(tabularium_core::embed::ENV_NO_EMBED, "1") };
    let raw = read_stdin()?;
    let input: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            if event != "user-prompt" {
                return Err(anyhow!("stdin is not valid hook JSON: {e}"));
            }
            serde_json::Value::Null
        }
    };
    let dir = Vault::resolve_dir(vault_dir.as_deref());
    if !Vault::exists(&dir) {
        return Ok(());
    }
    let mut v = Vault::open(&dir).map_err(|e| anyhow!("{e}"))?;
    load_writer_identity(&mut v, identity_dir.as_deref())?;
    if let Some(cwd) = input.get("cwd").and_then(|c| c.as_str()) {
        v.set_root(PathBuf::from(cwd));
    }
    match event {
        "user-prompt" => {
            let prompt = input.get("prompt").and_then(|p| p.as_str()).unwrap_or(raw.as_str());
            let h = v.hint(prompt, 3)?;
            if h.matched > 0 {
                let titles: Vec<String> = h.items.iter().map(|i| format!("\"{}\" ({})", i.title, short(&i.id))).collect();
                println!(
                    "Tabularium: {} related memor{} — {}. Call memory_recall to load them.",
                    h.matched,
                    if h.matched == 1 { "y" } else { "ies" },
                    titles.join("; ")
                );
            }
        }
        "post-tool" => handle_post_tool(&mut v, &input)?,
        other => return Err(anyhow!("unknown hook event '{other}' (expected user-prompt | post-tool)")),
    }
    Ok(())
}

/// Present tense a reader expects for the tool that touched the file. Read matters here as much as
/// Edit/Write/MultiEdit: what the agent *read* is exactly the ground truth a later `remember` should
/// cite as evidence, and a hook (not the agent's self-report) is the only way to record that it's real.
fn touch_verb(tool: &str) -> &'static str {
    match tool {
        "Read" => "read",
        "Write" => "wrote",
        "Edit" | "MultiEdit" | "NotebookEdit" => "edited",
        _ => "touched",
    }
}

/// Record a `PostToolUse` file touch as a tool-trust observation, evidence for a later `remember`.
/// Never fails the hook: a file it can't read (deleted mid-tool-call, race, permissions) just means
/// no hash is recorded, not a hard error.
fn handle_post_tool(v: &mut Vault, input: &serde_json::Value) -> Result<()> {
    let tool = input.get("tool_name").and_then(|t| t.as_str()).unwrap_or("tool");
    let Some(path) = input.pointer("/tool_input/file_path").and_then(|p| p.as_str()) else {
        return Ok(());
    };
    let hash = std::fs::read(path).ok().map(|b| tabularium_core::canon::blake3_hex(&b));
    let verb = touch_verb(tool);
    let content = match &hash {
        Some(h) => format!("{tool} {verb} {path} (blake3 {})", &h[..12]),
        None => format!("{tool} {verb} {path}"),
    };
    v.observe(ObserveInput {
        kind: EventKind::Observation,
        content,
        trust: Some(Trust::Tool),
        channel: "hook:PostToolUse".into(),
        meta: Some(serde_json::json!({"tool_name": tool, "file_path": path, "blake3": hash})),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_verb_distinguishes_read_from_write() {
        assert_eq!(touch_verb("Read"), "read");
        assert_eq!(touch_verb("Write"), "wrote");
        assert_eq!(touch_verb("Edit"), "edited");
        assert_eq!(touch_verb("MultiEdit"), "edited");
        assert_eq!(touch_verb("NotebookEdit"), "edited");
        assert_eq!(touch_verb("Bash"), "touched");
    }

    #[test]
    fn post_tool_records_a_read_as_tool_trust_observation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let f = root.join("notes.md");
        std::fs::write(&f, "hello").unwrap();
        let mut v = Vault::init(&dir.path().join("vault"), "t", Some(&root)).unwrap();

        let input = serde_json::json!({"tool_name": "Read", "tool_input": {"file_path": f.to_string_lossy()}});
        handle_post_tool(&mut v, &input).unwrap();

        let (_seq, _hash) = v.head().unwrap();
        let events = v.events(0, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].trust, Trust::Tool);
        assert_eq!(events[0].channel, "hook:PostToolUse");
        let payload = events[0].payload.as_ref().unwrap();
        assert!(payload["content"].as_str().unwrap().contains("Read read"), "{payload}");
        assert!(payload["content"].as_str().unwrap().contains("blake3"), "{payload}");
    }

    #[test]
    fn post_tool_ignores_non_file_tools() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::init(&dir.path().join("vault"), "t", Some(dir.path())).unwrap();
        let input = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "ls"}});
        handle_post_tool(&mut v, &input).unwrap();
        assert_eq!(v.events(0, 10).unwrap().len(), 0);
    }
}
