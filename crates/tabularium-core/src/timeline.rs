//! Zero-config audit visualizer: a single self-contained HTML file (inlined CSS/JS, no CDN, no
//! network) rendering the ledger's timeline and every active memory's evidence chain -- who
//! (which writer, at what trust) contributed to what the agent now "knows". Meant to make trust
//! provenance *scannable*: `audit()`/`verify()` already prove the chain is intact; this is for a
//! human looking at it and immediately seeing, e.g., an unregistered writer's events sitting
//! behind a `fact` memory, or which specific utterance backs a `preference`.
//!
//! Pure string generation from already-fetched data -- no I/O here. `Vault::render_timeline_html`
//! (`vault.rs`) does the fetching.

use crate::types::{Event, EventKind, Memory};
use crate::vault::WriterPolicy;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct TimelineData<'a> {
    vault_name: &'a str,
    head_seq: u64,
    head_hash: &'a str,
    generated_at: String,
    event_count_total: u64,
    events: Vec<serde_json::Value>,
    memories: &'a [Memory],
    writers: &'a BTreeMap<String, WriterPolicy>,
}

/// An `embed` event's payload is a bare float vector (hundreds to thousands of hex chars) with no
/// human-meaningful content -- shipping it in full would bloat "self-contained file" for no
/// benefit nobody reads. Every other event kind serializes unchanged.
fn compact_event(e: &Event) -> serde_json::Value {
    let mut v = serde_json::to_value(e).unwrap_or(serde_json::Value::Null);
    if e.kind == EventKind::Embed
        && let Some(hex) = v.pointer("/payload/vector_hex").and_then(|h| h.as_str())
    {
        let bytes = hex.len() / 2;
        v["payload"]["vector_hex"] = json!(format!("[{bytes} bytes, omitted from export]"));
    }
    v
}

/// Renders the visualizer. `events` should already be the window the caller wants shown (see
/// `Vault::render_timeline_html`'s `limit`); `event_count_total` is the ledger's real total, shown
/// in the header so a truncated view says so honestly instead of implying it's everything.
pub fn render(
    vault_name: &str,
    head_seq: u64,
    head_hash: &str,
    event_count_total: u64,
    events: &[Event],
    memories: &[Memory],
    writers: &BTreeMap<String, WriterPolicy>,
) -> String {
    let data = TimelineData {
        vault_name,
        head_seq,
        head_hash,
        generated_at: crate::vault::now_rfc3339(),
        event_count_total,
        events: events.iter().map(compact_event).collect(),
        memories,
        writers,
    };
    let json = serde_json::to_string(&data).unwrap_or_else(|_| "{}".to_string());
    // `</script>` inside the embedded JSON (it can't appear in this data, but defense in depth
    // costs nothing) would otherwise close the script tag early.
    let json = json.replace("</script>", "<\\/script>");
    TEMPLATE.replace("__TABULARIUM_DATA__", &json)
}

impl crate::vault::Vault {
    /// Renders the zero-config timeline visualizer for this vault, windowed to the most recent
    /// `limit` events (all memories, active and inactive, are always included -- there are far
    /// fewer of them than events, and seeing a forgotten or superseded one's former evidence trail
    /// is exactly the kind of thing an audit tool is for).
    pub fn render_timeline_html(&self, limit: usize) -> crate::error::Result<String> {
        let total = self.event_count()?;
        let after = total.saturating_sub(limit as u64);
        let events = self.events(after, limit)?;
        let memories = self.memories(true)?;
        let (seq, hash) = self.head()?;
        Ok(render(&self.config().name, seq, &hash, total, &events, &memories, &self.config().policy.writers))
    }
}

const TEMPLATE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>tabularium timeline</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #f7f7f5; --panel: #ffffff; --border: #e2e2df; --text: #1c1c1a; --muted: #6b6b66;
  --user: #1f8a4c; --agent: #2563b0; --tool: #b8860b; --external: #c0392b;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #17181a; --panel: #202225; --border: #33353a; --text: #e8e8e6; --muted: #9a9a96; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 16px; background: var(--bg); color: var(--text); font: 14px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif; }
header { margin-bottom: 16px; }
h1 { font-size: 18px; margin: 0 0 4px; }
.sub { color: var(--muted); font-size: 12px; }
.layout { display: grid; grid-template-columns: minmax(0,1.4fr) minmax(0,1fr); gap: 16px; align-items: start; }
@media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 12px; }
.panel h2 { font-size: 14px; margin: 0 0 10px; }
.controls { display: flex; flex-wrap: wrap; gap: 6px 14px; margin-bottom: 12px; font-size: 12px; }
.controls label { display: inline-flex; gap: 4px; align-items: center; cursor: pointer; }
input[type=search] { width: 100%; padding: 6px 8px; margin-bottom: 12px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg); color: var(--text); font: inherit; }
.row { border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; margin-bottom: 8px; background: var(--bg); }
.row.hidden { display: none; }
.row-head { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; font-size: 12px; }
.seq { color: var(--muted); font-variant-numeric: tabular-nums; }
.pill { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 11px; font-weight: 600; color: #fff; }
.trust-user { background: var(--user); } .trust-agent { background: var(--agent); }
.trust-tool { background: var(--tool); } .trust-external { background: var(--external); }
.kind { border: 1px solid var(--border); border-radius: 10px; padding: 1px 7px; font-size: 11px; color: var(--muted); }
.writer { font-family: ui-monospace, Consolas, monospace; font-size: 11px; color: var(--muted); }
.writer.unregistered { color: var(--external); font-weight: 600; }
.content { margin-top: 6px; white-space: pre-wrap; word-break: break-word; }
.redacted { color: var(--muted); font-style: italic; }
.evidence { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px; }
.chip { font-family: ui-monospace, Consolas, monospace; font-size: 10px; padding: 1px 6px; border: 1px solid var(--border); border-radius: 8px; cursor: pointer; background: var(--panel); }
.chip:hover { border-color: var(--agent); }
.subject { color: var(--muted); font-size: 11px; }
.flash { animation: flash 1.2s ease; }
@keyframes flash { 0% { outline: 2px solid var(--agent); } 100% { outline: 2px solid transparent; } }
.empty { color: var(--muted); font-style: italic; }
</style>
</head>
<body>
<header>
  <h1 id="title">tabularium timeline</h1>
  <div class="sub" id="subtitle"></div>
</header>
<div class="layout">
  <section class="panel">
    <h2>Ledger events</h2>
    <input type="search" id="search" placeholder="Search content, channel, writer...">
    <div class="controls" id="trust-filters"></div>
    <div id="events"></div>
  </section>
  <section class="panel">
    <h2>Memories (evidence chains)</h2>
    <div id="memories"></div>
  </section>
</div>
<script>
const DATA = __TABULARIUM_DATA__;

function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
}
function trustPill(t) { return `<span class="pill trust-${t}">${t}</span>`; }
function writerLabel(pubkey) {
  if (!pubkey) return '<span class="writer">vault key</span>';
  const w = DATA.writers[pubkey];
  const short = pubkey.slice(0, 10) + '…';
  if (w) return `<span class="writer">${short} ('${esc(w.name)}', max ${w.max_trust})</span>`;
  return `<span class="writer unregistered">${short} (unregistered)</span>`;
}

function renderEvents() {
  const el = document.getElementById('events');
  if (DATA.events.length === 0) { el.innerHTML = '<p class="empty">no events in this window</p>'; return; }
  el.innerHTML = DATA.events.map(e => {
    const content = e.payload
      ? `<div class="content">${esc(JSON.stringify(e.payload)).slice(0, 600)}</div>`
      : `<div class="content redacted">[redacted]</div>`;
    return `<div class="row" id="ev-${e.id}" data-kind="${e.kind}" data-trust="${e.trust}"
                 data-blob="${esc((e.channel + ' ' + (e.payload ? JSON.stringify(e.payload) : '') + ' ' + (e.writer_pubkey||'')).toLowerCase())}">
      <div class="row-head">
        <span class="seq">#${e.seq}</span>
        <span class="kind">${e.kind}</span>
        ${trustPill(e.trust)}
        <span class="subject">${esc(e.channel)}</span>
        ${writerLabel(e.writer_pubkey)}
        <span class="subject">${e.ts}</span>
      </div>
      ${content}
    </div>`;
  }).join('');
}

function renderMemories() {
  const el = document.getElementById('memories');
  if (DATA.memories.length === 0) { el.innerHTML = '<p class="empty">no memories</p>'; return; }
  const byId = {};
  for (const e of DATA.events) byId[e.id] = e;
  el.innerHTML = DATA.memories.map(m => {
    const state = m.tombstoned ? 'forgotten' : (m.superseded_by ? 'superseded' : 'active');
    const evidence = (m.evidence || []).map(id => {
      const e = byId[id];
      const label = e ? `#${e.seq} ${e.kind}/${e.trust}` : id.slice(0, 8);
      return `<span class="chip" onclick="jumpTo('${id}')">${esc(label)}</span>`;
    }).join('') || '<span class="empty">no cited evidence</span>';
    return `<div class="row">
      <div class="row-head">
        <span class="kind">${m.kind}</span>
        ${trustPill(m.trust)}
        <span class="subject">${state}</span>
        ${m.subject ? `<span class="subject">subject: ${esc(m.subject)}</span>` : ''}
      </div>
      <div class="content">${esc(m.text || '')}</div>
      <div class="evidence">${evidence}</div>
    </div>`;
  }).join('');
}

function jumpTo(id) {
  const row = document.getElementById('ev-' + id);
  if (!row) return;
  row.scrollIntoView({behavior: 'smooth', block: 'center'});
  row.classList.remove('flash'); void row.offsetWidth; row.classList.add('flash');
}

function applyFilters() {
  const q = document.getElementById('search').value.toLowerCase();
  const active = [...document.querySelectorAll('#trust-filters input:checked')].map(i => i.value);
  for (const row of document.querySelectorAll('#events .row')) {
    const matchesText = !q || row.dataset.blob.includes(q);
    const matchesTrust = active.includes(row.dataset.trust);
    row.classList.toggle('hidden', !(matchesText && matchesTrust));
  }
}

function init() {
  document.getElementById('title').textContent = `tabularium timeline — ${DATA.vault_name}`;
  document.getElementById('subtitle').textContent =
    `head #${DATA.head_seq} (${DATA.head_hash.slice(0, 16)}…) · showing ${DATA.events.length} of ${DATA.event_count_total} events · generated ${DATA.generated_at}`;
  const trusts = ['user', 'agent', 'tool', 'external'];
  document.getElementById('trust-filters').innerHTML = trusts.map(t =>
    `<label>${trustPill(t)} <input type="checkbox" value="${t}" checked onchange="applyFilters()"></label>`).join('');
  document.getElementById('search').addEventListener('input', applyFilters);
  renderEvents();
  renderMemories();
}
init();
</script>
</body>
</html>
"##;
