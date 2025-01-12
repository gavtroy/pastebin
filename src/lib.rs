extern crate flatbuffers;

use std::io;
use std::sync::Arc;
use std::time::SystemTime;

use flatbuffers::FlatBufferBuilder;
use rocket::State;
use rocket::http::CookieJar;
use rocket::tokio;
use rocksdb::{compaction_filter, DBWithThreadMode};

pub type DB = DBWithThreadMode<rocksdb::SingleThreaded>;

use sha2::Sha256;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

#[path = "api_generated.rs"]
mod api_generated;
use crate::api_generated::api::{finish_entry_buffer, root_as_entry, Entry, EntryArgs};

use phf::{phf_map};

static EXTENSIONS: phf::Map<&'static str, &'static str> = phf_map! {
    "log" => "log",
    "text" => "txt",
    "bash" => "sh",
    "c" => "c",
    "cpp" => "cpp",
    "css" => "css",
    "diff" => "diff",
    "go" => "go",
    "markup" => "xml",
    "java" => "java",
    "javascript" => "js",
    "json" => "json",
    "perl" => "pl",
    "php" => "php",
    "python" => "py",
    "ruby" => "rb",
    "rust" => "rs",
    "yaml" => "yaml",
    "actionscript" => "as",
    "armasm" => "s",
    "aspnet" => "aspx",
    "autohotkey" => "ahk",
    "autoit" => "au3",
    "awk" => "awk",
    "basic" => "bas",
    "batch" => "bat",
    "clike" => "c",
    "csharp" => "cs",
    "clojure" => "clj",
    "coffeescript" => "coffee",
    "cobol" => "cob",
    "csv" => "csv",
    "d" => "d",
    "dart" => "dart",
    "fortran" => "for",
    "groovy" => "groovy",
    "haskell" => "hs",
    "ini" => "ini",
    "kotlin" => "kt",
    "latex" => "tex",
    "less" => "less",
    "lisp" => "lisp",
    "lua" => "lua",
    "markdown" => "md",
    "objectivec" => "m",
    "ocaml" => "ml",
    "opencl" => "cl",
    "pascal" => "pas",
    "powershell" => "ps1",
    "processing" => "pde",
    "prolog" => "pl",
    "r" => "R",
    "jsx" => "jsx",
    "tsx" => "tsx",
    "rest" => "rst",
    "sass" => "sass",
    "scss" => "scss",
    "scala" => "scala",
    "scheme" => "scm",
    "sql" => "sql",
    "swift" => "swift",
    "tcl" => "tcl",
    "typescript" => "ts",
    "vbnet" => "vb",
    "verilog" => "v",
    "vhdl" => "vhdl",
    "visual-basic" => "vbs",
    "wasm" => "wasm",
    "wiki" => "wiki"
};

#[macro_export]
macro_rules! load_static_resources(
    { $($key:expr => $value:expr),+ } => {
        {
            let mut resources: HashMap<&'static str, &'static [u8]> = HashMap::new();
            $(
                resources.insert($key, include_bytes!($value));
            )*

            resources
        }
     };
);

pub fn compaction_filter_expired_entries(
    _: u32,
    _: &[u8],
    value: &[u8],
) -> compaction_filter::Decision {
    use compaction_filter::Decision::*;

    let entry = root_as_entry(value).unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();

    if entry.expiry_timestamp() != 0 && now >= entry.expiry_timestamp() {
        Remove
    } else {
        Keep
    }
}

pub fn get_extension(filename: &str) -> &str {
    filename
        .rfind('.')
        .map(|idx| &filename[idx..])
        .filter(|ext| ext.chars().skip(1).all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("")
}

pub fn get_ext_from_lang(mut lang: &str, encrypted: bool) -> String {
    if lang.contains("diff-") {
        lang = "diff";
    }
    let ext = EXTENSIONS.get(lang).unwrap_or(&"txt");
    if encrypted {
        return format!("{}.bin", ext);
    }
    String::from(*ext)
}

pub async fn get_entry_data(id: &str, db: &State<Arc<DB>>) -> Result<Vec<u8>, io::Error> {
    // read data from DB to Entry struct
    let my_id = String::from(id);
    let my_db = db.inner().clone();
    let lookup = tokio::task::spawn_blocking(move || {
        my_db.get(my_id).unwrap()
    }).await?;
    let root = match lookup {
        Some(root) => root,
        None => return Err(io::Error::new(io::ErrorKind::NotFound, "record not found")),
    };
    let entry = root_as_entry(&root).unwrap();

    // check if data expired (might not be yet deleted by rocksb compaction hook)
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();

    if entry.expiry_timestamp() != 0 && now >= entry.expiry_timestamp() {
        db.delete(id).unwrap();
        return Err(io::Error::new(io::ErrorKind::NotFound, "record not found"));
    }

    // "burn" one time only pastebin content
    if entry.burn() {
        db.delete(id).unwrap();
    }

    Ok(root)
}

pub async fn new_entry(
    id: &str,
    db: &State<Arc<DB>>,
    data: &mut rocket::data::DataStream<'_>,
    lang: String,
    ttl: u64,
    burn: bool,
    encrypted: bool,
    auth_token: Option<String>,
) {
    let mut bldr = FlatBufferBuilder::new();

    bldr.reset();

    // potential speed improvement over the create_vector:
    // https://docs.rs/flatbuffers/0.6.1/flatbuffers/struct.FlatBufferBuilder.html#method.create_vector
    let mut tmp_vec: Vec<u8> = vec![];
    tokio::io::copy(data, &mut tmp_vec).await.unwrap();

    bldr.start_vector::<u8>(tmp_vec.len());
    for byte in tmp_vec.iter().rev() {
        bldr.push::<u8>(*byte);
    }
    let data_vec = bldr.end_vector::<u8>(tmp_vec.len());

    // calc expiry datetime
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();
    let expiry = if ttl == 0 { ttl } else { now + ttl };

    // setup actual struct
    let args = EntryArgs {
        create_timestamp: now,
        expiry_timestamp: expiry,
        data: Some(data_vec),
        lang: Some(bldr.create_string(&lang)),
        burn,
        encrypted,
        owner_hmac: auth_token.and_then(|auth_token| {
            let mut mac = HmacSha256::new_from_slice(auth_token.as_bytes()).unwrap();
            mac.update(id.as_bytes());
            Some(bldr.create_vector(&mac.finalize().into_bytes()[..16]))
        }),
    };

    let user_offset = Entry::create(&mut bldr, &args);
    finish_entry_buffer(&mut bldr, user_offset);

    let my_id = String::from(id);
    let my_db = db.inner().clone();
    let _ = tokio::task::spawn_blocking(move || {
        my_db.put(my_id, bldr.finished_data().to_vec()).unwrap();
    }).await;
}

pub fn have_auth_token(
    entry: Entry,
    id: &str,
    cookies: &CookieJar<'_>,
) -> bool {
    let stored_hmac = match entry.owner_hmac() {
        Some(token) => token,
        None => return true,
    };
    let auth_token = match cookies.get("auth-token") {
        Some(cookie) => cookie.value(),
        None => return false,
    };
    let mut mac = HmacSha256::new_from_slice(auth_token.as_bytes()).unwrap();
    mac.update(id.as_bytes());
    mac.verify_truncated_left(stored_hmac.bytes()).is_ok()
}
