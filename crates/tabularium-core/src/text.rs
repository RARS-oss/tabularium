//! Deterministic text utilities: tokenizer, BM25, token estimator.
//!
//! Everything here is a pure function of its inputs. No randomness, no locale, no time.

use std::collections::{BTreeMap, HashMap};

pub const BM25_K1: f64 = 1.2;
pub const BM25_B: f64 = 0.75;

/// Lowercase alphanumeric runs (Unicode-aware). Tokens shorter than two chars are dropped
/// unless they are digits.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            for lc in ch.to_lowercase() {
                cur.push(lc);
            }
        } else if !cur.is_empty() {
            push_token(&mut tokens, std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        push_token(&mut tokens, cur);
    }
    tokens
}

fn push_token(tokens: &mut Vec<String>, tok: String) {
    let n = tok.chars().count();
    if n >= 2 || tok.chars().all(|c| c.is_ascii_digit()) {
        tokens.push(tok);
    }
}

/// Conservative token estimate. Over-estimates relative to common BPE tokenizers so that a
/// budget enforced with this estimator is never exceeded in real tokens.
///
/// ASCII word: ceil(len / 3). Non-ASCII chars: ceil(n / 2). Each punctuation/symbol: 1.
pub fn estimate_tokens(text: &str) -> u32 {
    let mut total: u32 = 0;
    let mut ascii_run: u32 = 0;
    let mut non_ascii: u32 = 0;
    let flush = |ascii_run: &mut u32, total: &mut u32| {
        if *ascii_run > 0 {
            *total += ascii_run.div_ceil(3);
            *ascii_run = 0;
        }
    };
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            ascii_run += 1;
        } else if ch.is_ascii_whitespace() {
            flush(&mut ascii_run, &mut total);
        } else if ch.is_ascii() {
            flush(&mut ascii_run, &mut total);
            total += 1;
        } else {
            flush(&mut ascii_run, &mut total);
            non_ascii += 1;
        }
    }
    flush(&mut ascii_run, &mut total);
    total + non_ascii.div_ceil(2)
}

/// A document in the BM25 index.
#[derive(Debug, Clone)]
pub struct Doc<K> {
    pub key: K,
    pub tokens: Vec<String>,
}

/// Exact, deterministic BM25 over a small corpus. Built fresh per query set; corpora here are
/// the active memories of one vault, which is small.
pub struct Bm25<K> {
    docs: Vec<Doc<K>>,
    df: HashMap<String, u32>,
    avgdl: f64,
}

impl<K: Clone> Bm25<K> {
    pub fn build(docs: Vec<Doc<K>>) -> Bm25<K> {
        let mut df: HashMap<String, u32> = HashMap::new();
        let mut total_len: usize = 0;
        for d in &docs {
            total_len += d.tokens.len();
            let mut seen: Vec<&str> = Vec::new();
            for t in &d.tokens {
                if !seen.contains(&t.as_str()) {
                    seen.push(t);
                    *df.entry(t.clone()).or_insert(0) += 1;
                }
            }
        }
        let avgdl = if docs.is_empty() { 0.0 } else { total_len as f64 / docs.len() as f64 };
        Bm25 { docs, df, avgdl }
    }

    pub fn len(&self) -> usize {
        self.docs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    fn idf(&self, term: &str) -> f64 {
        let n = self.docs.len() as f64;
        let df = *self.df.get(term).unwrap_or(&0) as f64;
        ((n - df + 0.5) / (df + 0.5) + 1.0).ln()
    }

    /// Scores every document against the query. Query terms are deduplicated preserving first
    /// occurrence so summation order is fixed. Returns (key, score) in document order.
    pub fn score_all(&self, query_tokens: &[String]) -> Vec<(K, f64)> {
        let mut terms: Vec<&String> = Vec::new();
        for t in query_tokens {
            if !terms.contains(&t) {
                terms.push(t);
            }
        }
        let mut out = Vec::with_capacity(self.docs.len());
        for d in &self.docs {
            let dl = d.tokens.len() as f64;
            let mut tf: BTreeMap<&str, u32> = BTreeMap::new();
            for t in &d.tokens {
                *tf.entry(t.as_str()).or_insert(0) += 1;
            }
            let mut score = 0.0;
            for term in &terms {
                let f = *tf.get(term.as_str()).unwrap_or(&0) as f64;
                if f == 0.0 {
                    continue;
                }
                let norm = if self.avgdl > 0.0 { dl / self.avgdl } else { 1.0 };
                let denom = f + BM25_K1 * (1.0 - BM25_B + BM25_B * norm);
                score += self.idf(term) * (f * (BM25_K1 + 1.0)) / denom;
            }
            out.push((d.key.clone(), score));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_handles_unicode_and_code() {
        assert_eq!(tokenize("Hello, World! foo_bar x1 a"), vec!["hello", "world", "foo_bar", "x1"]);
        assert_eq!(tokenize("Привет, Мир"), vec!["привет", "мир"]);
    }

    #[test]
    fn estimator_is_conservative_and_monotone() {
        assert_eq!(estimate_tokens(""), 0);
        assert!(estimate_tokens("hello world") >= 2);
        assert!(estimate_tokens("hello world, again") > estimate_tokens("hello world"));
        assert!(estimate_tokens("Привет мир") >= 4);
    }

    #[test]
    fn bm25_ranks_matching_doc_first() {
        let idx = Bm25::build(vec![
            Doc { key: 1, tokens: tokenize("the cat sat on the mat") },
            Doc { key: 2, tokens: tokenize("rust ledger hash chain") },
            Doc { key: 3, tokens: tokenize("a signed ledger of events") },
        ]);
        let scores = idx.score_all(&tokenize("ledger chain"));
        let best = scores.iter().max_by(|a, b| a.1.partial_cmp(&b.1).unwrap()).unwrap();
        assert_eq!(best.0, 2);
        assert_eq!(scores[0].1, 0.0);
    }
}
