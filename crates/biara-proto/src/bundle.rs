//! Render-bundle artifact: one file holding every named analysis record.
//!
//! Serde-only contract shared by the worker service and bundle readers.
//! [`BundleWriter`] stages named JSON records (`cfg/<addr:x>`, `xrefs`,
//! `abi`, `decomp/<addr:x>`, `index`, ...) in memory and streams them to disk
//! on [`BundleWriter::finish`], committing a footer index plus a fixed-size
//! trailer; [`BundleReader`] loads that footer over any `Read + Seek` source
//! (file, in-memory cursor, WASM range client) and fetches entries by byte
//! range. No LLVM, QEMU, OS or HTTP types.
//!
//! File layout (all integers little-endian):
//!
//! ```text
//! [record]* [footer JSON] [footer_len: u64] [magic "BND1": u32] [version 1: u32]
//! record = [name_len: u32][name bytes][payload_len: u64][payload JSON bytes]
//! footer = {"version":1,"entries":{"<name>":{"offset":u64,"length":u64}}}
//! ```
//!
//! `offset` is the absolute file offset of the payload JSON bytes. Duplicate
//! names staged before one `finish` are last-wins in memory; committed bytes
//! are never mutated. Incremental publish keeps the O(bundle) bytes but not
//! the O(bundle) JSON: byte-copy `[0, records_end)` into a fresh sink with
//! [`copy_prefix`], [`BundleWriter::adopt`] the prior index snapshot, append
//! only the new records, then `finish`. Clients fetch individual records with
//! HTTP Range requests: `GET` the last 16 bytes for the trailer,
//! `GET [len-16-footer_len, len-16)` for the footer, then
//! `GET [offset, offset+length)` for any entry. [`BundleReader::get`] performs
//! exactly those seeks/reads against its source.
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom, Write},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Bundle read/write failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bundle io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bundle codec: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bundle entry missing: {0:?}")]
    Missing(String),
    #[error("unsupported bundle version {0}")]
    Version(u32),
    #[error("bundle footer corrupt: {0}")]
    Footer(String),
    #[error("bundle name invalid: {0:?}")]
    Name(String),
}

const BUNDLE_MAGIC: u32 = u32::from_le_bytes(*b"BND1");
const BUNDLE_VERSION: u32 = 1;
const TRAILER_LEN: u64 = 16;

/// Byte-copy a committed record prefix `[0, end)` from `source` into `sink`
/// with a bounded 128 KiB buffer: O(bytes) disk I/O, O(1) memory, no JSON
/// decode. Both streams are left at `end`. Used with
/// [`BundleReader::records_end`] + [`BundleWriter::adopt`] for incremental
/// atomic publish (prior footer index, new record bytes, new footer).
pub fn copy_prefix<R: Read + Seek, W: Write + Seek>(
    source: &mut R,
    sink: &mut W,
    end: u64,
) -> Result<u64, Error> {
    source.seek(SeekFrom::Start(0))?;
    sink.seek(SeekFrom::Start(0))?;
    let mut remaining = end;
    let mut buffer = [0u8; 128 * 1024];
    while remaining > 0 {
        let want = (remaining.min(buffer.len() as u64)) as usize;
        let n = source.read(&mut buffer[..want])?;
        if n == 0 {
            return Err(Error::Footer("bundle prefix truncated".into()));
        }
        sink.write_all(&buffer[..n])?;
        remaining -= n as u64;
    }
    Ok(end)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct EntryLocation {
    offset: u64,
    length: u64,
}

/// Stages named records in memory and commits them to one bundle file.
///
/// `append` only buffers (`name -> payload JSON`); `finish` computes record
/// offsets, streams every record plus the footer/trailer, flushes, and syncs
/// only when the caller syncs the returned handle. Nothing partial is ever
/// readable: either the previous committed footer still parses, or the new
/// footer does. Crashes mid-`finish` leave a torn tail the next reader
/// rejects as [`Error::Footer`]; writers recover by rebuilding from staged
/// state, never by patching bytes.
pub struct BundleWriter<S = std::fs::File> {
    sink: S,
    staged: BTreeMap<String, serde_json::Value>,
    adopted: BTreeMap<String, EntryLocation>,
}

impl<S> BundleWriter<S>
where
    S: Write + Seek,
{
    /// Buffer records; nothing is written until [`Self::finish`].
    pub fn new(sink: S) -> Result<Self, Error> {
        Ok(Self {
            sink,
            staged: BTreeMap::new(),
            adopted: BTreeMap::new(),
        })
    }

    /// Stage one named record, replacing any earlier staged record under
    /// `name`. Committed bytes are untouched until [`Self::finish`].
    pub fn append<T: Serialize>(&mut self, name: &str, value: &T) -> Result<(), Error> {
        if name.is_empty() {
            return Err(Error::Name(name.to_owned()));
        }
        self.staged
            .insert(name.to_owned(), serde_json::to_value(value)?);
        Ok(())
    }

    /// Adopt a prior footer index when the sink already holds that bundle's
    /// committed record prefix (see [`BundleReader::records_end`] +
    /// byte-copy below). Committed names stay addressable; staged appends
    /// with the same name shadow them at the next `finish` without rewriting
    /// the surviving prefix. Callers MUST ensure the sink's bytes
    /// `[0, records_end)` are exactly the prefix the index was read from;
    /// mismatched bytes decode as corrupt payloads, never as silent success.
    pub fn adopt(&mut self, name: String, offset: u64, length: u64) {
        self.adopted.insert(name, EntryLocation { offset, length });
    }
    /// Stream all staged records plus the footer index and trailer, flush,
    /// and return the sink; the caller syncs it durable before publishing.
    /// Offsets are computed from a zero base when the sink is fresh, or from
    /// the current end when continuing an unfinished stream.
    pub fn finish(mut self) -> Result<S, Error> {
        let base = self.sink.stream_position()?;
        let mut offset = base;
        let mut index = std::mem::take(&mut self.adopted);
        // BTreeMap iteration is sorted, so committed order is deterministic.
        // Staged names shadow adopted ones (e.g. the refreshed `index`).
        for (name, payload) in std::mem::take(&mut self.staged) {
            let bytes = serde_json::to_vec(&payload)?;
            let name_bytes = name.as_bytes();
            let name_len =
                u32::try_from(name_bytes.len()).map_err(|_| Error::Name(name.clone()))?;
            let payload_len = bytes.len() as u64;
            self.sink.write_all(&name_len.to_le_bytes())?;
            self.sink.write_all(name_bytes)?;
            self.sink.write_all(&payload_len.to_le_bytes())?;
            let payload_offset = offset + 4 + name_bytes.len() as u64 + 8;
            self.sink.write_all(&bytes)?;
            index.insert(
                name,
                EntryLocation {
                    offset: payload_offset,
                    length: payload_len,
                },
            );
            offset = payload_offset + payload_len;
        }
        let footer = serde_json::to_vec(&serde_json::json!({
            "version": BUNDLE_VERSION,
            "entries": index,
        }))?;
        self.sink.write_all(&footer)?;
        let footer_len = footer.len() as u64;
        self.sink.write_all(&footer_len.to_le_bytes())?;
        self.sink.write_all(&BUNDLE_MAGIC.to_le_bytes())?;
        self.sink.write_all(&BUNDLE_VERSION.to_le_bytes())?;
        self.sink.flush()?;
        Ok(self.sink)
    }
}

/// Random access by byte range over a committed bundle.
///
/// `new` reads only the 16-byte trailer plus the footer JSON; entry payloads
/// stay in the source until `get` seeks to their indexed range. The source is
/// any `Read + Seek` byte stream: a file, an in-memory cursor, or a WASM
/// range-fetch adapter.
pub struct BundleReader<S = std::fs::File> {
    source: S,
    index: BTreeMap<String, EntryLocation>,
    records_end: u64,
}

impl<S> BundleReader<S>
where
    S: Read + Seek,
{
    /// Load the footer index; fetch entries with [`Self::get`].
    pub fn new(mut source: S) -> Result<Self, Error> {
        let len = source.seek(SeekFrom::End(0))?;
        let footer_start = len.checked_sub(TRAILER_LEN).ok_or_else(|| {
            Error::Footer("bundle shorter than footer trailer".into())
        })?;
        source.seek(SeekFrom::Start(footer_start))?;
        let mut trailer = [0u8; 16];
        source.read_exact(&mut trailer)?;
        let footer_len = u64::from_le_bytes(trailer[0..8].try_into().unwrap());
        let magic = u32::from_le_bytes(trailer[8..12].try_into().unwrap());
        let version = u32::from_le_bytes(trailer[12..16].try_into().unwrap());
        if magic != BUNDLE_MAGIC {
            return Err(Error::Footer("bundle trailer magic mismatch".into()));
        }
        if version != BUNDLE_VERSION {
            return Err(Error::Version(version));
        }
        let records_end = footer_start
            .checked_sub(footer_len)
            .ok_or_else(|| Error::Footer("trailer length exceeds file".into()))?;
        let footer_size: usize = footer_len
            .try_into()
            .map_err(|_| Error::Footer("footer too large".into()))?;
        source.seek(SeekFrom::Start(records_end))?;
        let mut raw = vec![0u8; footer_size];
        source.read_exact(&mut raw)?;
        let footer: serde_json::Value = serde_json::from_slice(&raw)?;
        let footer_version = footer.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        if footer_version != u64::from(BUNDLE_VERSION) {
            return Err(Error::Version(footer_version as u32));
        }
        let mut index = BTreeMap::new();
        if let Some(map) = footer.get("entries").and_then(|v| v.as_object()) {
            for (name, loc) in map {
                let loc: EntryLocation = serde_json::from_value(loc.clone())?;
                if loc
                    .offset
                    .checked_add(loc.length)
                    .is_none_or(|end| end > records_end)
                {
                    return Err(Error::Footer(format!(
                        "entry {name:?} range exceeds records"
                    )));
                }
                index.insert(name.clone(), loc);
            }
        }
        Ok(Self {
            source,
            index,
            records_end,
        })
    }

    /// Fetch and decode one named record, reading only its indexed byte range.
    pub fn get<T: DeserializeOwned>(&mut self, name: &str) -> Result<T, Error> {
        let loc = self
            .index
            .get(name)
            .copied()
            .ok_or_else(|| Error::Missing(name.to_owned()))?;
        let length: usize = loc
            .length
            .try_into()
            .map_err(|_| Error::Footer(format!("entry {name:?} too large")))?;
        self.source.seek(SeekFrom::Start(loc.offset))?;
        let mut payload = vec![0u8; length];
        self.source.read_exact(&mut payload)?;
        serde_json::from_slice(&payload).map_err(Error::Json)
    }

    /// Whether `name` is present in the footer.
    pub fn contains(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }

    /// Indexed record names in stable sorted order.
    pub fn names(&self) -> Vec<String> {
        self.index.keys().cloned().collect()
    }

    /// Number of indexed records.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the bundle holds no records.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Byte range (`offset`, `length`) of `name`'s payload for HTTP Range
    /// fetches; `None` for missing names.
    pub fn entry_range(&self, name: &str) -> Option<(u64, u64)> {
        self.index.get(name).map(|loc| (loc.offset, loc.length))
    }

    /// End of the committed record prefix: bytes `[0, records_end)` are the
    /// records the footer indexes; bytes at/after are footer + trailer.
    pub fn records_end(&self) -> u64 {
        self.records_end
    }

    /// Owned footer snapshot (`name -> (payload offset, payload length)`).
    /// Pass each entry to [`BundleWriter::adopt`] after byte-copying
    /// `[0, records_end)` into a fresh sink; staged appends then shadow
    /// adopted names. Owned (no borrow): the reader can drop before publish.
    pub fn index_snapshot(&self) -> BTreeMap<String, (u64, u64)> {
        self.index
            .iter()
            .map(|(name, loc)| (name.clone(), (loc.offset, loc.length)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Seek, SeekFrom};

    #[test]
    fn roundtrip_streams_and_serves_single_ranges() {
        let mut writer = BundleWriter::new(Cursor::new(Vec::new())).unwrap();
        writer.append("index", &serde_json::json!({"n":1})).unwrap();
        writer.append("decomp/10", &serde_json::json!({"body":"a"})).unwrap();
        // Last-wins without corrupting the survivor.
        writer.append("index", &serde_json::json!({"n":2})).unwrap();
        let bytes = writer.finish().unwrap().into_inner();

        let mut reader = BundleReader::new(Cursor::new(bytes.clone())).unwrap();
        assert_eq!(reader.len(), 2);
        assert!(!reader.is_empty());
        assert!(reader.contains("index"));
        assert!(!reader.contains("missing"));
        assert_eq!(
            reader.names(),
            vec!["decomp/10".to_owned(), "index".to_owned()]
        );
        let index: serde_json::Value = reader.get("index").unwrap();
        assert_eq!(index, serde_json::json!({"n":2}));
        assert!(reader.get::<serde_json::Value>("missing").is_err());
        assert!(reader.entry_range("missing").is_none());

        // Manual byte-range fetch equals the indexed read (HTTP Range shape).
        let (offset, length) = reader.entry_range("decomp/10").unwrap();
        let ranged: serde_json::Value =
            serde_json::from_slice(&bytes[offset as usize..(offset + length) as usize]).unwrap();
        let mut again = BundleReader::new(Cursor::new(bytes.clone())).unwrap();
        let indexed: serde_json::Value = again.get("decomp/10").unwrap();
        assert_eq!(ranged, indexed);

        // Trailer is a fixed 16-byte footer pointer.
        let len = bytes.len() as u64;
        let trailer = &bytes[(len - 16) as usize..];
        assert_eq!(&trailer[8..12], b"BND1");
        assert_eq!(u32::from_le_bytes(trailer[12..16].try_into().unwrap()), 1);
        let footer_len = u64::from_le_bytes(trailer[0..8].try_into().unwrap());
        let records_end = len - 16 - footer_len;
        for name in reader.names() {
            let (o, l) = reader.entry_range(&name).unwrap();
            assert!(o + l <= records_end, "{name} range exceeds records");
        }
    }

    #[test]
    fn prefix_copy_publishes_without_decoding_prior_payloads() {
        let mut writer = BundleWriter::new(Cursor::new(Vec::new())).unwrap();
        writer.append("index", &serde_json::json!({"n":1})).unwrap();
        writer
            .append("decomp/10", &serde_json::json!({"body":"a"}))
            .unwrap();
        let committed = writer.finish().unwrap().into_inner();
        let reader = BundleReader::new(Cursor::new(committed.clone())).unwrap();
        // Incremental publish: copy raw record bytes, adopt the footer index,
        // append one record, commit. Prior payloads are never decoded.
        let mut next = Cursor::new(Vec::new());
        let mut source = Cursor::new(committed);
        copy_prefix(&mut source, &mut next, reader.records_end()).unwrap();
        let mut writer = BundleWriter::new(next).unwrap();
        for (name, (offset, length)) in reader.index_snapshot() {
            writer.adopt(name, offset, length);
        }
        writer
            .append("decomp/20", &serde_json::json!({"body":"b"}))
            .unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let mut reader = BundleReader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(reader.len(), 3);
        let first: serde_json::Value = reader.get("decomp/10").unwrap();
        assert_eq!(first, serde_json::json!({"body":"a"}));
        let added: serde_json::Value = reader.get("decomp/20").unwrap();
        assert_eq!(added, serde_json::json!({"body":"b"}));
    }

    #[test]
    fn file_sink_roundtrip_matches_cursor() {
        let dir = std::env::temp_dir().join(format!(
            "biara-bundle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.bundle");
        let mut writer =
            BundleWriter::new(std::fs::File::create(&path).unwrap()).unwrap();
        writer.append("index", &serde_json::json!({"n":7})).unwrap();
        writer.finish().unwrap().sync_all().unwrap();
        let mut reader =
            BundleReader::new(std::fs::File::open(&path).unwrap()).unwrap();
        let index: serde_json::Value = reader.get("index").unwrap();
        assert_eq!(index, serde_json::json!({"n":7}));
        // Seek back to start still resolves the footer (no whole-file read).
        let mut file = std::fs::File::open(&path).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut reader = BundleReader::new(file).unwrap();
        assert!(reader.contains("index"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
