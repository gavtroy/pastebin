#![feature(proc_macro_hygiene, decl_macro)]
#![allow(clippy::too_many_arguments)]

#[macro_use]
extern crate rocket;
extern crate structopt_derive;
extern crate chrono;
extern crate timeago;
extern crate flatbuffers;
extern crate handlebars;
extern crate nanoid;
extern crate num_cpus;
extern crate regex;
extern crate speculate2;
extern crate structopt;
extern crate ubyte;

mod formatter;

#[macro_use]
mod lib;
use lib::{DB, compaction_filter_expired_entries, get_entry_data, get_extension, new_entry, have_auth_token};

mod plugins;
use plugins::plugin::{Plugin, PluginManager};

mod api_generated;
use api_generated::api::root_as_entry;

use std::io;
use std::io::Cursor;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use rocket::config::{Config, TlsConfig};
use rocket::http::{ContentType, Status};
use rocket::http::{Cookie, CookieJar};
use rocket::response::{Redirect, Response};
use rocket::tokio;
use rocket::{Data, State};

use chrono::DateTime;
use handlebars::Handlebars;
use humantime::parse_duration;
use nanoid::nanoid;
use regex::Regex;
use rocksdb::Options;
use serde_json::json;
use speculate2::speculate;
use structopt::StructOpt;
use ubyte::ToByteUnit;

speculate! {
    use super::rocket;
    use rocket::local::blocking::Client;
    use rocket::http::Status;

    before {
        use tempdir::TempDir;

        // setup temporary database
        let tmp_dir = TempDir::new("rocks_db_test").unwrap();
        let file_path = tmp_dir.path().join("database");
        let mut pastebin_config = PastebinConfig::from_args();
        pastebin_config.db_path = file_path.to_str().unwrap().to_string();
        let rocket = rocket(pastebin_config);

        // init rocket client
        let client = Client::tracked(rocket).expect("invalid rocket instance");
    }

    #[allow(dead_code)]
    fn insert_data<'r>(client: &'r Client, data: &str, path: &str) -> String {
        let response = client.post(path)
            .body(data)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        // retrieve paste ID
        let url = response.into_string().unwrap();
        let id = url.split('/').collect::<Vec<&str>>().last().cloned().unwrap();

        id.to_string()
    }

    #[allow(dead_code)]
    fn get_data(client: &Client, path: String) -> rocket::local::blocking::LocalResponse {
        client.get(format!("/{}", path)).dispatch()
    }

    it "can get create and fetch paste" {
        // store data via post request
        let id = insert_data(&client, "random_test_data_to_be_checked", "/");

        // retrieve the data via get request
        let response = get_data(&client, id);
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.into_string().unwrap().contains("random_test_data_to_be_checked"));
    }

    it "can remove paste by id" {
        // allow auth-token cookie to be set
        get_data(&client, format!("/new"));

        let id = insert_data(&client, "random_test_data_dont_care", "/");
        let response = client.delete(format!("/{}", id)).dispatch();
        assert_eq!(response.status(), Status::Ok);

        let response = get_data(&client, format!("/{}", id).to_string());
        assert_eq!(response.status(), Status::NotFound);
    }

    it "can't remove paste without cookie" {
        // allow auth-token cookie to be set
        get_data(&client, format!("/new"));

        let id = insert_data(&client, "random_test_data_dont_care", "/");
        let response = client.delete(format!("/{}", id))
            .cookie(Cookie::new("auth-token", "abcdef"))
            .dispatch();
        assert_eq!(response.status(), Status::Unauthorized);

        let response = get_data(&client, format!("/{}", id).to_string());
        assert_eq!(response.status(), Status::Ok);
    }

    it "can remove non-existing paste" {
        let response = get_data(&client, "some_fake_id".to_string());
        assert_eq!(response.status(), Status::NotFound);

        let response = client.delete("/some_fake_id").dispatch();
        assert_eq!(response.status(), Status::NotFound);

        let response = get_data(&client, "some_fake_id".to_string());
        assert_eq!(response.status(), Status::NotFound);
    }

    it "can get raw contents" {
        // store data via post request
        let id = insert_data(&client, "random_test_data_to_be_checked", "/");

        // retrieve the data via get request
        let response = get_data(&client, format!("raw/{}", id));
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::Plain));
        assert!(response.into_string().unwrap().contains("random_test_data_to_be_checked"));
    }

    it "can download contents" {
        // store data via post request
        let id = insert_data(&client, "random_test_data_to_be_checked", "/");

        // retrieve the data via get request
        let response = get_data(&client, format!("download/{}", id));
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::Binary));
        assert!(response.into_string().unwrap().contains("random_test_data_to_be_checked"));
    }

    it "can clone contents" {
        // store data via post request
        let id = insert_data(&client, "random_test_data_to_be_checked", "/");

        // retrieve the data via get request
        let response = get_data(&client, format!("new?id={}", id));
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.into_string().unwrap().contains("random_test_data_to_be_checked"));
    }

    it "can't get burned paste" {
        // store data via post request
        let id = insert_data(&client, "random_test_data_to_be_checked", "/?burn=true");
        let response = get_data(&client, id.clone());
        assert_eq!(response.status(), Status::Ok);

        // retrieve the data via get request
        let response = get_data(&client, id);
        assert_eq!(response.status(), Status::NotFound);
    }

    it "can't get expired paste" {
        use std::{thread, time};

        // store data via post request
        let id = insert_data(&client, "random_test_data_to_be_checked", "/?ttl=1");
        let response = get_data(&client, id.clone());
        assert_eq!(response.status(), Status::Ok);

        thread::sleep(time::Duration::from_secs(1));

        // retrieve the data via get request
        let response = get_data(&client, id);
        assert_eq!(response.status(), Status::NotFound);
    }

    it "can get static contents" {
        let response = client.get("/static/favicon.ico").dispatch();
        let contents = std::fs::read("static/favicon.ico").unwrap();

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_bytes(), Some(contents));
    }

    it "can cope with invalid unicode data" {
        let invalid_data = unsafe {
            String::from_utf8_unchecked(b"Hello \xF0\x90\x80World".to_vec())
        };
        let id = insert_data(&client, &invalid_data, "/");

        let response = get_data(&client, id);
        assert_eq!(response.status(), Status::Ok);
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(StructOpt, Debug)]
#[structopt(
    name = "pastebin",
    about = "Simple, standalone and fast pastebin service."
)]
struct PastebinConfig {
    #[structopt(
        long = "address",
        help = "IP address to listen on",
        default_value = "127.0.0.1"
    )]
    address: IpAddr,

    #[structopt(
        long = "port",
        help = "Port number to listen on",
        default_value = "8000"
    )]
    port: u16,

    #[structopt(
        long = "workers",
        help = "Number of concurrent thread workers",
        default_value = "0"
    )]
    workers: usize,

    #[structopt(
        long = "keep-alive",
        help = "Keep-alive timeout in seconds",
        default_value = "5"
    )]
    keep_alive: u32,

    #[structopt(long = "log", help = "Max log level", default_value = "normal")]
    log: rocket::config::LogLevel,

    #[structopt(
        long = "ttl",
        help = "Time to live for entries, by default kept forever",
        default_value = "0"
    )]
    ttl: u64,

    #[structopt(
        long = "db",
        help = "Database file path",
        default_value = "./pastebin.db"
    )]
    db_path: String,

    #[structopt(long = "tls-certs", help = "Path to certificate chain in PEM format")]
    tls_certs: Option<String>,

    #[structopt(
        long = "tls-key",
        help = "Path to private key for tls-certs in PEM format"
    )]
    tls_key: Option<String>,

    #[structopt(long = "uri", help = "Override default URI")]
    uri: Option<String>,

    #[structopt(
        long = "uri-prefix",
        help = "Prefix appended to the URI (ie. '/pastebin')",
        default_value = ""
    )]
    uri_prefix: String,

    #[structopt(
        long = "slug-charset",
        help = "Character set (expressed as rust compatible regex) to use for generating the URL slug",
        default_value = "[A-Za-z0-9]"
    )]
    slug_charset: String,

    #[structopt(long = "slug-len", help = "Length of URL slug", default_value = "9")]
    slug_len: usize,

    #[structopt(
        long = "ui-expiry-times",
        help = "List of paste expiry times redered in the UI dropdown selector",
        default_value = "10 minutes, 1 hour, 1 day, 1 week, 1 month, 1 year, Never"
    )]
    ui_expiry_times: Vec<String>,

    #[structopt(long = "ui-line-numbers", help = "Display line numbers")]
    ui_line_numbers: bool,

    #[structopt(long = "ui-burn", help = "Display burn option")]
    ui_burn: bool,

    #[structopt(
        long = "plugins",
        help = "Enable additional functionalities (ie. prism, mermaid)",
        default_value = "prism"
    )]
    plugins: Vec<String>,
}

/* Wrapper for quick migration from Rocket 0.4.0, in theory temporary */
struct Responder<'r>(rocket::response::Response<'r>);

impl<'r> rocket::response::Responder<'r, 'r> for Responder<'r> {
    fn respond_to(self, _: &'r rocket::request::Request<'_>) -> rocket::response::Result<'r> {
        Ok(self.0)
    }
}

fn get_url(cfg: &PastebinConfig) -> String {
    let port = if vec![443, 80].contains(&cfg.port) {
        String::from("")
    } else {
        format!(":{}", cfg.port)
    };
    let scheme = if cfg.tls_certs.is_some() {
        "https"
    } else {
        "http"
    };

    if cfg.uri.is_some() {
        cfg.uri.clone().unwrap()
    } else {
        format!(
            "{scheme}://{address}{port}",
            scheme = scheme,
            port = port,
            address = cfg.address,
        )
    }
}

fn get_error_response<'r>(
    handlebars: &Handlebars<'r>,
    uri_prefix: String,
    html: String,
    status: Status,
) -> Responder<'r> {
    let map = json!({
        "version": VERSION,
        "is_error": "true",
        "uri_prefix": uri_prefix,
    });

    let content = handlebars.render_template(html.as_str(), &map).unwrap();

    Responder(
        Response::build()
            .status(status)
            .header(ContentType::HTML)
            .sized_body(content.len(), Cursor::new(content))
            .finalize()
    )
}

#[post("/?<lang>&<ttl>&<burn>&<encrypted>", data = "<paste>")]
async fn create(
    paste: Data<'_>,
    state: &State<Arc<DB>>,
    cfg: &State<PastebinConfig>,
    alphabet: &State<Vec<char>>,
    lang: Option<String>,
    ttl: Option<u64>,
    burn: Option<bool>,
    encrypted: Option<bool>,
    cookies: &CookieJar<'_>,
) -> Result<String, io::Error> {
    let slug_len = cfg.inner().slug_len;
    let id = nanoid!(slug_len, alphabet.inner());
    let url = format!("{url}{uri_prefix}/{id}", url = get_url(cfg.inner()), uri_prefix = cfg.uri_prefix, id = id);

    new_entry(
        &id,
        state,
        &mut paste.open(2.megabytes()),
        lang.unwrap_or_else(|| String::from("markup")),
        ttl.unwrap_or(cfg.ttl),
        burn.unwrap_or(false),
        encrypted.unwrap_or(false),
        cookies.get("auth-token").map(|c| c.value().to_string()),
    ).await;

    Ok(url)
}

#[delete("/<id>")]
async fn remove<'r>(
    id: &str,
    state: &State<Arc<DB>>,
    cookies: &CookieJar<'_>,
) -> Responder<'r> {
    let root = match get_entry_data(id, state).await {
        Ok(x) => x,
        Err(_) => return Responder(Response::build().status(Status::NotFound).finalize()),
    };

    if !have_auth_token(root_as_entry(&root).unwrap(), &id, cookies) {
        return Responder(Response::build().status(Status::Unauthorized).finalize());
    }

    match state.delete(id) {
        Ok(_) => Responder(Response::build().finalize()),
        _ => Responder(Response::build().status(Status::InternalServerError).finalize()),
    }
}

#[get("/<id>?<lang>")]
async fn get<'r>(
    id: &str,
    lang: Option<&str>,
    state: &State<Arc<DB>>,
    handlebars: &State<Handlebars<'r>>,
    plugin_manager: &State<PluginManager<'r>>,
    ui_expiry_times: &State<Vec<(String, u64)>>,
    ui_expiry_default: &State<String>,
    cfg: &State<PastebinConfig>,
    cookies: &CookieJar<'_>,
) -> Responder<'r> {
    let resources = plugin_manager.static_resources();
    let html = String::from_utf8_lossy(resources.get("/static/index.html").unwrap()).to_string();

    // handle missing entry
    let root = match get_entry_data(id, state).await {
        Ok(x) => x,
        Err(e) => {
            let err_kind = match e.kind() {
                io::ErrorKind::NotFound => Status::NotFound,
                _ => Status::InternalServerError,
            };

            let map = json!({
                "version": VERSION,
                "is_error": "true",
                "uri_prefix": cfg.uri_prefix,
                "js_imports": plugin_manager.js_imports(),
                "css_imports": plugin_manager.css_imports(),
                "js_init": plugin_manager.js_init(),
            });

            let content = handlebars.render_template(html.as_str(), &map).unwrap();

            return Responder(
                Response::build()
                    .status(err_kind)
                    .header(ContentType::HTML)
                    .sized_body(content.len(), Cursor::new(content))
                    .finalize()
                );
        }
    };

    // handle existing entry
    let entry = root_as_entry(&root).unwrap();
    let selected_lang = lang
        .unwrap_or_else(|| entry.lang().unwrap())
        .to_lowercase();

    let mut pastebin_cls = Vec::new();
    if cfg.ui_line_numbers {
        pastebin_cls.push("line-numbers".to_string());
    }

    pastebin_cls.push(format!("language-{}", selected_lang));

    let mut map = json!({
        "is_created": "true",
        "pastebin_code": String::from_utf8_lossy(entry.data().unwrap().bytes()),
        "pastebin_id": id,
        "lang": selected_lang,
        "pastebin_cls": pastebin_cls.join(" "),
        "version": VERSION,
        "uri_prefix": cfg.uri_prefix,
        "ui_expiry_times": ui_expiry_times.inner(),
        "ui_expiry_default": ui_expiry_default.inner(),
        "js_imports": plugin_manager.js_imports(),
        "css_imports": plugin_manager.css_imports(),
        "js_init": plugin_manager.js_init(),
        "can_delete": have_auth_token(entry, &id, cookies),
    });

    if entry.burn() {
        map["msg"] = json!("FOR YOUR EYES ONLY. The paste is gone, after you close this window.");
        map["level"] = json!("warning");
        map["is_burned"] = json!("true");
        map["glyph"] = json!("fa fa-fire");
    } else if entry.expiry_timestamp() != 0 {
        let mut timeto = timeago::Formatter::new();
        timeto.ago("");
        let now_timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let dur = Duration::from_secs(entry.expiry_timestamp() - now_timestamp);
        let time = DateTime::from_timestamp(entry.expiry_timestamp() as i64, 0).unwrap();
        map["expiry"] = json!(format!("Expires in {}", timeto.convert(dur)));
        map["expiry_title"] = json!(format!("Paste expires at {}", time.format("%Y-%m-%d %H:%M:%S")));
    }

    if entry.encrypted() {
        map["is_encrypted"] = json!("true");
    }

    let content = handlebars.render_template(html.as_str(), &map).unwrap();

    Responder(
        Response::build()
            .status(Status::Ok)
            .header(ContentType::HTML)
            .sized_body(content.len(), Cursor::new(content))
            .finalize()
    )
}

#[get("/new?<id>&<level>&<msg>&<glyph>&<url>")]
async fn get_new<'r>(
    state: &State<Arc<DB>>,
    handlebars: &State<Handlebars<'r>>,
    cfg: &State<PastebinConfig>,
    plugin_manager: &State<PluginManager<'r>>,
    ui_expiry_times: &State<Vec<(String, u64)>>,
    ui_expiry_default: &State<String>,
    id: Option<&str>,
    level: Option<&str>,
    glyph: Option<&str>,
    msg: Option<&str>,
    url: Option<&str>,
    cookies: &CookieJar<'_>,
) -> Responder<'r> {
    let resources = plugin_manager.static_resources();
    let html = String::from_utf8_lossy(resources.get("/static/index.html").unwrap()).to_string();
    let msg = msg.unwrap_or("");
    let level = level.unwrap_or("secondary");
    let glyph = glyph.unwrap_or("");
    let url = url.unwrap_or("");

    let auth_token = match cookies.get("auth-token") {
        Some(cookie) => cookie.value().to_string(),
        _ => nanoid!(),
    };
    let mut cookie = Cookie::new("auth-token", auth_token);
    cookie.make_permanent();
    cookies.add(cookie);

    let mut map = json!({
        "is_editable": "true",
        "version": VERSION,
        "msg": msg,
        "level": level,
        "glyph": glyph,
        "url": url,
        "uri_prefix": cfg.uri_prefix,
        "ui_expiry_times": ui_expiry_times.inner(),
        "ui_expiry_default": ui_expiry_default.inner(),
        "ui_burn": cfg.ui_burn,
        "js_imports": plugin_manager.js_imports(),
        "css_imports": plugin_manager.css_imports(),
        "js_init": plugin_manager.js_init(),
    });

    if let Some(id) = id {
        let _ = get_entry_data(id, state).await.map(|root| {
            let entry = root_as_entry(&root).unwrap();

            if entry.encrypted() {
                map["is_encrypted"] = json!("true");
            }

            map["pastebin_code"] = json!(std::str::from_utf8(entry.data().unwrap().bytes()).unwrap());
        });
    }

    let content = handlebars.render_template(html.as_str(), &map).unwrap();

    Responder(
        Response::build()
            .status(Status::Ok)
            .header(ContentType::HTML)
            .sized_body(content.len(), Cursor::new(content))
            .finalize()
    )
}

#[get("/raw/<id>")]
async fn get_raw(id: &str, state: &State<Arc<DB>>) -> Responder<'static> {
    // handle missing entry
    let root = match get_entry_data(id, state).await {
        Ok(x) => x,
        Err(e) => {
            let err_kind = match e.kind() {
                io::ErrorKind::NotFound => Status::NotFound,
                _ => Status::InternalServerError,
            };

            return Responder(Response::build().status(err_kind).finalize());
        }
    };

    let entry = root_as_entry(&root).unwrap();
    let mut data: Vec<u8> = vec![];

    tokio::io::copy(&mut entry.data().unwrap().bytes(), &mut data).await.unwrap();

    Responder(
        Response::build()
            .status(Status::Ok)
            .header(ContentType::Plain)
            .sized_body(data.len(), Cursor::new(data))
            .finalize()
    )
}

#[get("/download/<id>")]
async fn get_binary(id: &str, state: &State<Arc<DB>>) -> Responder<'static> {
    let Responder(response) = get_raw(id, state).await;
    Responder(
        Response::build_from(response)
            .header(ContentType::Binary)
            .finalize()
    )
}

#[get("/static/<resource..>")]
async fn get_static<'r>(
    resource: PathBuf,
    handlebars: &State<Handlebars<'_>>,
    plugin_manager: &State<PluginManager<'_>>,
    cfg: &State<PastebinConfig>,
) -> Responder<'r> {
    let resources = plugin_manager.static_resources();
    let pth = Path::new("/static/").join(resource);
    let pth_str = pth.to_string_lossy();
    let ext = get_extension(&pth_str).replace(".", "");

    let content = match resources.get(pth_str.as_ref()) {
        Some(data) => data,
        None => {
            let html =
                String::from_utf8_lossy(resources.get("/static/index.html").unwrap()).to_string();

            return get_error_response(
                handlebars.inner(),
                cfg.uri_prefix.clone(),
                html,
                Status::NotFound,
            );
        }
    };
    let content_type = ContentType::from_extension(ext.as_str()).unwrap();

    Responder(
        Response::build()
            .status(Status::Ok)
            .header(content_type)
            .sized_body(content.len(), Cursor::new(content.iter()))
            .finalize()
    )
}

#[get("/")]
async fn index(cfg: &State<PastebinConfig>) -> Redirect {
    let url = String::from(
        Path::new(cfg.uri_prefix.as_str())
            .join("new")
            .to_str()
            .unwrap(),
    );

    Redirect::to(url)
}

fn rocket(pastebin_config: PastebinConfig) -> rocket::Rocket<rocket::Build> {
    // parse command line opts
    let workers = if pastebin_config.workers != 0 {
        pastebin_config.workers
    } else {
        num_cpus::get() * 2
    };
    let mut rocket_config = Config {
        address: pastebin_config.address.clone(),
        port: pastebin_config.port,
        workers: workers,
        keep_alive: pastebin_config.keep_alive,
        log_level: pastebin_config.log,
        ..Default::default()
    };

    // handle tls cert setup
    if pastebin_config.tls_certs.is_some() && pastebin_config.tls_key.is_some() {
        rocket_config.tls = Some(TlsConfig::from_paths(
            pastebin_config.tls_certs.clone().unwrap().as_str(),
            pastebin_config.tls_key.clone().unwrap().as_str(),
        ))
    }

    // setup db

    let db = Arc::new(DB::open_default(pastebin_config.db_path.clone()).unwrap());
    let mut db_opts = Options::default();

    db_opts.create_if_missing(true);
    db_opts.set_compaction_filter("ttl_entries", compaction_filter_expired_entries);

    // define slug URL alphabet
    let alphabet = {
        let re = Regex::new(&pastebin_config.slug_charset).unwrap();

        let mut tmp = [0; 4];
        let mut alphabet: Vec<char> = vec![];

        // match all printable ASCII characters
        for i in 0x20..0x7e as u8 {
            let c = i as char;

            if re.is_match(c.encode_utf8(&mut tmp)) {
                alphabet.push(c.clone());
            }
        }

        alphabet
    };

    // setup drop down expiry menu (for instance 1m, 20m, 1 year, never)
    let ui_expiry_times = {
        let mut all = vec![];
        for item in pastebin_config.ui_expiry_times.clone() {
            for sub_elem in item.split(',') {
                if sub_elem.trim().to_lowercase() == "never" {
                    all.push((sub_elem.trim().to_string(), 0));
                } else {
                    all.push((
                        sub_elem.trim().to_string(),
                        parse_duration(sub_elem).unwrap().as_secs()
                    ));
                }
            }
        }

        all
    };

    let ui_expiry_default: String = ui_expiry_times
        .iter()
        .filter_map(|(name, val)| {
            if *val == pastebin_config.ttl {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect();

    if ui_expiry_default.is_empty() {
        panic!("the TTL flag should match one of the ui-expiry-times option");
    }

    if pastebin_config.slug_len == 0 {
        panic!("slug_len must be larger than zero");
    }

    if alphabet.len() == 0 {
        panic!("selected slug alphabet is empty, please check if slug_charset is a valid regex");
    }

    let plugins: Vec<Box<dyn Plugin>> = pastebin_config
        .plugins
        .iter()
        .map(|t| match t.as_str() {
            "prism" => Box::new(plugins::prism::new()),
            "mermaid" => Box::new(plugins::mermaid::new()),
            _ => panic!("unknown plugin provided"),
        })
        .map(|x| x as Box<dyn plugins::plugin::Plugin>)
        .collect();

    let plugin_manager = plugins::new(plugins);
    let uri_prefix = pastebin_config.uri_prefix.clone();

    // run rocket
    rocket::custom(rocket_config)
        .manage(pastebin_config)
        .manage(db)
        .manage(formatter::new())
        .manage(plugin_manager)
        .manage(alphabet)
        .manage(ui_expiry_times)
        .manage(ui_expiry_default)
        .mount(
            if uri_prefix == "" {
                "/"
            } else {
                uri_prefix.as_str()
            },
            routes![index, create, remove, get, get_new, get_raw, get_binary, get_static],
        )
}

#[launch]
fn rocket_main() -> _ {
    let pastebin_config = PastebinConfig::from_args();
    rocket(pastebin_config)
}
