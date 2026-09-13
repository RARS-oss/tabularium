//! Embeddings: a pluggable embedder, vector encoding for the ledger, and cosine similarity.
//!
//! Vectors are computed once at ingest and written to the ledger as `embed` events, so a rebuilt
//! vault carries bit-identical vectors and recall never depends on which machine re-embeds.
//! Only the *query* is embedded live; its similarity scores are quantized before ranking.

use crate::error::{Error, Result};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Anything that turns text into fixed-size vectors. Implementations must be deterministic for a
/// given model id on a given machine; cross-machine drift is absorbed by storing vectors once.
pub trait Embedder: Send {
    /// Stable identifier recorded in every embed event, e.g. `fastembed:paraphrase-multilingual-MiniLM-L12-v2-q`.
    fn model_id(&self) -> &str;
    fn dim(&self) -> usize;
    /// Returns one L2-normalized vector per input text.
    fn embed(&mut self, texts: &[&str]) -> Result<Vec<Vec<f32>>>;
}

/// Deterministic feature-hashing embedder for tests and offline experiments. Not semantic.
pub struct HashEmbedder {
    dim: usize,
    id: String,
}

impl HashEmbedder {
    pub fn new(dim: usize) -> HashEmbedder {
        HashEmbedder { dim, id: format!("hash:{dim}") }
    }
}

impl Embedder for HashEmbedder {
    fn model_id(&self) -> &str {
        &self.id
    }

    fn dim(&self) -> usize {
        self.dim
    }

    fn embed(&mut self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        Ok(texts
            .iter()
            .map(|t| {
                let mut v = vec![0f32; self.dim];
                for tok in crate::text::tokenize(t) {
                    let mut h = DefaultHasher::new();
                    tok.hash(&mut h);
                    let x = h.finish();
                    let idx = (x % self.dim as u64) as usize;
                    let sign = if (x >> 63) == 0 { 1.0 } else { -1.0 };
                    v[idx] += sign;
                }
                normalize(&mut v);
                v
            })
            .collect())
    }
}

/// L2-normalize in place. A zero vector stays zero.
pub fn normalize(v: &mut [f32]) {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

/// Dot product of two normalized vectors, summed in index order (deterministic).
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Round a similarity to 4 decimals so tiny cross-machine differences cannot reorder ties.
pub fn quantize(x: f32) -> f32 {
    (x * 10_000.0).round() / 10_000.0
}

/// Little-endian f32 bytes, hex encoded. Exact round trip.
pub fn encode_vector(v: &[f32]) -> String {
    let mut bytes = Vec::with_capacity(v.len() * 4);
    for x in v {
        bytes.extend_from_slice(&x.to_le_bytes());
    }
    hex::encode(bytes)
}

pub fn decode_vector(hex_str: &str) -> Result<Vec<f32>> {
    let bytes = hex::decode(hex_str).map_err(|e| Error::Invalid(format!("bad vector hex: {e}")))?;
    if bytes.len() % 4 != 0 {
        return Err(Error::Invalid("vector byte length is not a multiple of 4".into()));
    }
    Ok(vector_from_bytes(&bytes))
}

pub fn vector_to_bytes(v: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(v.len() * 4);
    for x in v {
        bytes.extend_from_slice(&x.to_le_bytes());
    }
    bytes
}

/// Decode little-endian f32s; a trailing partial chunk is ignored.
pub fn vector_from_bytes(bytes: &[u8]) -> Vec<f32> {
    bytes.as_chunks::<4>().0.iter().map(|c| f32::from_le_bytes(*c)).collect()
}

/// Embedding settings stored in `vault.toml`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmbeddingConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Model name understood by [`onnx::model_from_name`]. Recorded in every embed event.
    #[serde(default = "default_model")]
    pub model: String,
    /// Minimum quantized cosine for a memory to count as a semantic match.
    #[serde(default = "default_threshold")]
    pub threshold: f32,
    /// Lower semantic-match threshold used only for a query/candidate pair whose dominant scripts
    /// differ (`text::Script::crosses`, e.g. a Russian query against an English memory). Never
    /// raises the effective threshold: values above `threshold` are clamped down to it.
    #[serde(default = "default_cross_script_threshold")]
    pub cross_script_threshold: f32,
    /// Minimum quantized cosine between two differently-`subject`ed active memories for
    /// `Vault::contradictions` to flag them as a possible conflict. Higher than `threshold`
    /// because this needs "same specific claim", not "same topic".
    #[serde(default = "default_contradiction_threshold")]
    pub contradiction_threshold: f32,
    /// Minimum quantized cosine for `Vault::duplicates` to flag two active memories (any subjects,
    /// including none) as near-duplicates worth consolidating. Higher still than
    /// `contradiction_threshold`: a duplicate should be near-identical text, not just overlapping.
    #[serde(default = "default_duplicate_threshold")]
    pub duplicate_threshold: f32,
    /// Model cache directory. Default: `~/.tabularium/models`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<String>,
}

fn default_enabled() -> bool {
    true
}

pub const DEFAULT_MODEL: &str = "paraphrase-multilingual-MiniLM-L12-v2-q";

fn default_model() -> String {
    DEFAULT_MODEL.to_string()
}

fn default_threshold() -> f32 {
    0.30
}

/// Calibrated by dogfooding against `evals/language/ru_en_rrf.py`'s real ONNX multilingual
/// embedder (2026-09-13): a mixed RU/EN vault's genuinely-correct cross-script matches (the model
/// puts each one at or near rank 1 among same-direction candidates) land at cosine 0.077-0.62 --
/// often well under `threshold`'s monolingual calibration of 0.30, so they were being dropped
/// before they could even be ranked (7/20 cross-script queries in that eval never found their
/// target at all). 0.20 recovers every case in that run where the correct match was 0.20-0.29 and
/// still the best cross-script candidate, without admitting wrong-topic cross-script noise ahead
/// of it: the off-diagonal (wrong-topic) cosines that newly clear 0.20 topped out around 0.30,
/// never above the true match's own score in the same query. Below 0.20 the remaining misses
/// (e.g. "фича-флаги" vs. "feature flags" at cosine -0.002) are a real embedding-quality limit,
/// not a threshold problem -- no cutoff recovers a negative cosine without also flooding every
/// other query with noise.
fn default_cross_script_threshold() -> f32 {
    0.20
}

/// Calibrated by dogfooding against a real vault (2026-09-13): the multilingual MiniLM model puts
/// two genuinely-drifted paraphrased plans (`build-priority-order` vs `planned-projects-list`,
/// same roadmap, one updated and one not) at cosine 0.544 — well under an initial guess of 0.72,
/// which caught nothing. 0.50 catches that real case with a small margin.
fn default_contradiction_threshold() -> f32 {
    0.50
}

/// Calibrated by dogfooding against a real vault (2026-09-13): the model puts even the most
/// topically-related distinct memories at cosine <= 0.771, real paraphrases of the same fact
/// noticeably lower still (~0.48), while near-verbatim text (casing/punctuation/a synonym swap)
/// lands at 0.98+ and exact repeats at 1.0. 0.90 sits in the gap between "related" and
/// "near-verbatim", so it only flags the latter.
fn default_duplicate_threshold() -> f32 {
    0.90
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        EmbeddingConfig {
            enabled: true,
            model: default_model(),
            threshold: default_threshold(),
            cross_script_threshold: default_cross_script_threshold(),
            contradiction_threshold: default_contradiction_threshold(),
            duplicate_threshold: default_duplicate_threshold(),
            cache_dir: None,
        }
    }
}

/// Environment variable that disables embeddings for a process (hooks, tests, CI).
pub const ENV_NO_EMBED: &str = "TABULARIUM_NO_EMBED";

#[cfg(feature = "fastembed")]
pub mod onnx {
    use super::{normalize, Embedder};
    use crate::error::{Error, Result};
    use fastembed::{EmbeddingModel, TextEmbedding, TextInitOptions};
    use std::path::Path;

    /// Map a human model name to a fastembed variant. Names are case-insensitive.
    pub fn model_from_name(name: &str) -> Option<EmbeddingModel> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "paraphrase-multilingual-minilm-l12-v2" => EmbeddingModel::ParaphraseMLMiniLML12V2,
            "paraphrase-multilingual-minilm-l12-v2-q" => EmbeddingModel::ParaphraseMLMiniLML12V2Q,
            "multilingual-e5-small" => EmbeddingModel::MultilingualE5Small,
            "multilingual-e5-base" => EmbeddingModel::MultilingualE5Base,
            "bge-m3" => EmbeddingModel::BGEM3,
            "all-minilm-l6-v2" => EmbeddingModel::AllMiniLML6V2,
            "bge-small-en-v1.5" => EmbeddingModel::BGESmallENV15,
            _ => return None,
        })
    }

    pub struct OnnxEmbedder {
        inner: TextEmbedding,
        id: String,
        dim: usize,
    }

    impl OnnxEmbedder {
        /// Loads (downloading on first use) the model into `cache_dir`.
        pub fn new(model_name: &str, cache_dir: &Path, show_progress: bool) -> Result<OnnxEmbedder> {
            let model = model_from_name(model_name)
                .ok_or_else(|| Error::Config(format!("unknown embedding model '{model_name}'")))?;
            let info = TextEmbedding::get_model_info(&model)
                .map_err(|e| Error::Config(format!("model info for '{model_name}': {e}")))?;
            let dim = info.dim;
            std::fs::create_dir_all(cache_dir)?;
            let inner = TextEmbedding::try_new(
                TextInitOptions::new(model)
                    .with_cache_dir(cache_dir.to_path_buf())
                    .with_show_download_progress(show_progress),
            )
            .map_err(|e| Error::Config(format!("cannot load embedding model '{model_name}': {e}")))?;
            Ok(OnnxEmbedder { inner, id: format!("fastembed:{}", model_name.trim().to_ascii_lowercase()), dim })
        }
    }

    impl Embedder for OnnxEmbedder {
        fn model_id(&self) -> &str {
            &self.id
        }

        fn dim(&self) -> usize {
            self.dim
        }

        fn embed(&mut self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            let mut out = self
                .inner
                .embed(texts, None)
                .map_err(|e| Error::Config(format!("embedding failed: {e}")))?;
            for v in out.iter_mut() {
                normalize(v);
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_roundtrip_is_exact() {
        let v = vec![0.1f32, -2.5, 3.0e-8, 1.0, f32::MIN_POSITIVE];
        assert_eq!(decode_vector(&encode_vector(&v)).unwrap(), v);
        assert_eq!(vector_from_bytes(&vector_to_bytes(&v)), v);
        assert!(decode_vector("abc").is_err());
    }

    #[test]
    fn hash_embedder_is_deterministic_and_normalized() {
        let mut e = HashEmbedder::new(32);
        let a = e.embed(&["ledger hash chain", "cats"]).unwrap();
        let b = e.embed(&["ledger hash chain", "cats"]).unwrap();
        assert_eq!(a, b);
        assert!((cosine(&a[0], &a[0]) - 1.0).abs() < 1e-5);
        assert!(cosine(&a[0], &a[1]).abs() < 0.999);
        assert_eq!(quantize(0.123456), 0.1235);
    }
}
