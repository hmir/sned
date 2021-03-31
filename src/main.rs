#[macro_use]
extern crate prettytable;

use app_dirs::{AppDataType, AppInfo};
use format_num::NumberFormat;
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::Table;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use sodiumoxide::base64;
use sodiumoxide::crypto::secretstream::{gen_key, Header, Key, Pull, Push, Stream, Tag, ABYTES};
use sodiumoxide::crypto::{box_, sign};
use std::io::{Cursor, Read, Write};
use std::path::PathBuf;
use std::time::Duration;
use std::{fmt, fs, io};
use structopt::StructOpt;

const APP_INFO: AppInfo = AppInfo {
    name: "sned",
    author: "hmir",
};

const PLAINTEXT_CHUNK_LEN: usize = 8196;
const CIPHERTEXT_CHUNK_LEN: usize = PLAINTEXT_CHUNK_LEN + ABYTES;

const CONNECTION_TIMEOUT_SECONDS: u64 = 30;

const AUTHENTICATOR_URL: &'static str = "authenticator";
const INBOX_URL: &'static str = "inbox";
const LIST_USERS_URL: &'static str = "list-users";
const REGISTER_URL: &'static str = "register";
const TRANSFER_URL: &'static str = "transfer";
const DOWNLOAD_URL: &'static str = "download";
const LOOKUP_URL: &'static str = "lookup";

const CUR_SERVER_PATH: &'static str = "cur_server.txt";
const USERNAME_PATH: &'static str = "username.txt";
const SECRET_KEY_PATH: &'static str = "secret_key";
const PUBLIC_KEY_PATH: &'static str = "public_key";
const SIGNING_SECRET_KEY_PATH: &'static str = "signing_secret_key";
const SIGNING_PUBLIC_KEY_PATH: &'static str = "signing_public_key";

const PORT: i32 = 8191;

#[derive(Debug)]
enum SnedError {
    AlreadyRegisteredError,
    ConnectionError,
    ItemDoesNotExistError(String),
    AsymmetricKeyParseError,
    SymmetricKeyParseError,
    OtherPublicKeyParseError,
    FileCreateError(String),
    FileOpenError(String),
    FileReadError(Option<String>),
    ConfigFilesError,
    ServerResponseError((reqwest::StatusCode, String)),
    ServerDoesNotExistError,
}

impl fmt::Display for SnedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnedError::AlreadyRegisteredError => {
                write!(f, "You have already registered a user for this server")
            }
            SnedError::ConnectionError => write!(f, "Error connecting to server"),
            SnedError::ItemDoesNotExistError(id) => {
                write!(f, "Transfer with id {} does not exist", id)
            }
            SnedError::AsymmetricKeyParseError => {
                write!(f, "Error parsing asymmetric key")
            }
            SnedError::SymmetricKeyParseError => {
                write!(f, "Error parsing symmetric key")
            }
            SnedError::OtherPublicKeyParseError => {
                write!(f, "Error parsing public key of this user")
            }
            SnedError::FileCreateError(file) => {
                write!(f, "Error creating file {}", file)
            }
            SnedError::FileOpenError(file) => {
                write!(f, "Error opening file {}", file)
            }
            SnedError::FileReadError(server) => {
                if let Some(s) = server {
                    write!(
                        f,
                        "Could not read username and/or key files at server {}",
                        s
                    )
                } else {
                    write!(f, "No servers found, you may need to run 'sned register'")
                }
            }
            SnedError::ServerResponseError((code, message)) => {
                write!(f, "{} error from server: '{}'", code.as_str(), message)
            }
            SnedError::ConfigFilesError => {
                write!(f, "Unknown configuration issue")
            }
            SnedError::ServerDoesNotExistError => {
                write!(f, "You do not have a registered user for this server")
            }
        }
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "sned")]
enum Sned {
    Whoami,
    Inbox,
    Lookup {
        username: String,
    },
    Register {
        username: String,
        server: String,
    },
    Transfer {
        file: PathBuf,
        recipients: Vec<String>,
        #[structopt(short, long)]
        name: Option<String>,
    },
    Download {
        id: String,
        file: PathBuf,
    },
    ChServer {
        server: String,
    },
    ListServers,
    ListUsers,
}

#[derive(Serialize)]
struct AuthenticatorRequestPayload {
    username: String,
}

#[derive(Serialize)]
struct LookupRequestPayload {
    username: String,
}

#[derive(Serialize)]
struct RegisterRequestPayload {
    username: String,
    public_key: String,
    signing_public_key: String,
}

#[derive(Serialize)]
struct InboxRequestPayload {
    username: String,
    signed_authenticator: String,
}

#[derive(Serialize)]
struct ListUsersRequestPayload {
    username: String,
    signed_authenticator: String,
}

#[derive(Serialize)]
struct DownloadRequestPayload {
    username: String,
    signed_authenticator: String,
    download_id: String,
}

#[derive(Serialize)]
struct TransferRequestPayload {
    sender: String,
    recipients: Vec<String>,
    name: String,
    signed_authenticator: String,
    shared_keys: Vec<String>,
    shared_header: String,
    shared_nonce: String,
    data_len: u64,
}

#[derive(Deserialize)]
struct InboxItem {
    download_id: String,
    sender: String,
    shared_key: String,
    shared_header: String,
    shared_nonce: String,
    date_created: String,
    file_name: String,
    file_size: u64,
}

#[derive(Deserialize)]
struct InboxItemList {
    items: Vec<InboxItem>,
}

fn generate_progress_bar(total_size: u64) -> ProgressBar {
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
                 .template("{spinner:.green} [{elapsed_precise}] [{bar:20.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                 .progress_chars("#>-"));
    pb
}

struct EncryptionReader<R: Read> {
    reader: R,
    encrypted_chunks: Vec<u8>,
    plaintext_buffer: [u8; PLAINTEXT_CHUNK_LEN],
    enc_stream: Stream<Push>,
    progress_bar: ProgressBar,
}

impl<R: Read> EncryptionReader<R> {
    pub fn new(reader: R, enc_stream: Stream<Push>, total_ciphertext_len: u64) -> Self {
        let progress_bar = generate_progress_bar(total_ciphertext_len);
        Self {
            reader,
            encrypted_chunks: Vec::new(),
            plaintext_buffer: [0; PLAINTEXT_CHUNK_LEN],
            enc_stream,
            progress_bar,
        }
    }
}

impl<R: Read> Read for EncryptionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.encrypted_chunks.len() < buf.len() {
            let plaintext_len = self.reader.read(&mut self.plaintext_buffer)?;

            // Internal reader already consumed, so we break to finish reading out encrypted chunks
            if plaintext_len == 0 {
                break;
            }

            let ciphertext = self
                .enc_stream
                .push(&self.plaintext_buffer[..plaintext_len], None, Tag::Message)
                .unwrap();
            self.encrypted_chunks.extend_from_slice(&ciphertext);

            // Reached EOF
            if plaintext_len < PLAINTEXT_CHUNK_LEN {
                break;
            }
        }

        let read = self.encrypted_chunks.as_slice().read(buf)?;
        self.encrypted_chunks.drain(0..read);

        self.progress_bar
            .set_position(self.progress_bar.position() + read as u64);

        if read == 0 {
            self.progress_bar.finish();
        }

        Ok(read)
    }
}

struct DecryptionWriter<W: Write> {
    writer: W,
    ciphertext_buffer: Vec<u8>,
    dec_stream: Stream<Pull>,
    progress_bar: ProgressBar,
}

impl<W: Write> DecryptionWriter<W> {
    pub fn new(writer: W, dec_stream: Stream<Pull>, total_plaintext_len: u64) -> Self {
        let progress_bar = generate_progress_bar(total_plaintext_len);
        Self {
            writer,
            ciphertext_buffer: Vec::new(),
            dec_stream,
            progress_bar,
        }
    }
    fn decrypt_slice(&mut self, end_index: usize) -> io::Result<Vec<u8>> {
        if let Ok(decrypted) = self
            .dec_stream
            .pull(&self.ciphertext_buffer[..end_index], None)
        {
            Ok(decrypted.0)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, ""))
        }
    }
}

impl<W: Write> Write for DecryptionWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ciphertext_buffer.extend_from_slice(buf);
        while self.ciphertext_buffer.len() >= CIPHERTEXT_CHUNK_LEN {
            let plaintext = self.decrypt_slice(CIPHERTEXT_CHUNK_LEN)?;

            self.writer.write(plaintext.as_slice())?;
            self.ciphertext_buffer.drain(0..CIPHERTEXT_CHUNK_LEN);

            self.progress_bar
                .set_position(self.progress_bar.position() + plaintext.len() as u64);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.ciphertext_buffer.len() > 0 {
            let plaintext = self.decrypt_slice(self.ciphertext_buffer.len())?;
            self.writer.write(plaintext.as_slice()).unwrap();

            self.progress_bar
                .set_position(self.progress_bar.position() + plaintext.len() as u64);
        }

        self.progress_bar.finish();
        self.writer.flush()
    }
}

fn generate_http_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(None)
        .connect_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECONDS))
        .build()
        .unwrap()
}

fn generate_response_result(
    response: Result<Response, reqwest::Error>,
) -> Result<Response, SnedError> {
    if let Ok(resp) = response {
        if !resp.status().is_success() {
            Err(SnedError::ServerResponseError((
                resp.status(),
                resp.text().unwrap_or("".to_string()),
            )))
        } else {
            Ok(resp)
        }
    } else {
        Err(SnedError::ConnectionError)
    }
}

fn make_json_post_request(relative_url: &str, json_payload: &str) -> Result<Response, SnedError> {
    let response = generate_http_client()
        .post(get_cur_server_url()? + relative_url)
        .header("Content-Type", "application/json")
        .body(json_payload.to_string())
        .send();
    generate_response_result(response)
}

fn get_path(relative_path: &str) -> Result<PathBuf, SnedError> {
    let mut path = get_app_root()?;
    path.push(relative_path);
    Ok(path)
}

fn get_server_path(relative_path: &str) -> Result<PathBuf, SnedError> {
    let server = get_cur_server()?;
    let mut path = get_path(&server)?;
    path.push(relative_path);
    Ok(path)
}

fn get_app_root() -> Result<PathBuf, SnedError> {
    app_dirs::app_root(AppDataType::UserConfig, &APP_INFO).map_err(|_| SnedError::ConfigFilesError)
}

fn get_cur_server() -> Result<String, SnedError> {
    let path = get_path(CUR_SERVER_PATH)?;
    fs::read_to_string(path).map_err(|_| SnedError::FileReadError(None))
}

fn get_cur_server_url() -> Result<String, SnedError> {
    let server = get_cur_server()?;
    Ok("https://".to_string() + &server + ":" + &PORT.to_string() + "/")
}

fn format_server_str(server: &str) -> String {
    let mut server = server.to_string();
    if server.starts_with("http://") {
        server.replace_range(..7, "");
    }

    if server.starts_with("https://") {
        server.replace_range(..8, "");
    }

    if server.ends_with("/") {
        server.pop();
    }

    server
}

fn set_cur_server(server: &str) -> Result<(), SnedError> {
    let path = get_path(CUR_SERVER_PATH)?;
    let server = format_server_str(server);
    if path.exists() && server.is_empty() {
        fs::remove_file(path).map_err(|_| SnedError::ConfigFilesError)
    } else {
        fs::write(path, server).map_err(|_| SnedError::ConfigFilesError)
    }
}

fn does_server_config_directory_exist(server: &str) -> Result<bool, SnedError> {
    let server = format_server_str(server);
    let path = get_path(&server)?;
    Ok(path.exists())
}

fn create_server_config_directory(server: &str) -> Result<(), SnedError> {
    let server = format_server_str(server);
    let path = get_path(&server)?;
    fs::create_dir(path).map_err(|_| SnedError::ConfigFilesError)
}

fn force_delete_server_config_directory(server: &str) {
    let server = format_server_str(server);
    let path = get_path(&server).unwrap();
    fs::remove_dir_all(path).unwrap()
}

fn write_server_config_file(relative_path: &str, contents: &[u8]) -> Result<(), SnedError> {
    fs::write(get_server_path(relative_path)?, contents).map_err(|_| SnedError::ConfigFilesError)
}

fn switch_servers(server: String) -> Result<(), SnedError> {
    let server = format_server_str(&server);
    let path = get_path(&server)?;
    if path.exists() {
        set_cur_server(&server)?;
        println!("Switched to server {}", server);
    } else {
        return Err(SnedError::ServerDoesNotExistError);
    }

    Ok(())
}

fn list_servers() -> Result<(), SnedError> {
    let path = get_app_root()?;
    let entries = path.read_dir().map_err(|_| SnedError::ConfigFilesError)?;
    for entry in entries {
        let entry = entry.map_err(|_| SnedError::ConfigFilesError)?;
        if entry.path().is_dir() {
            println!("{:?}", entry.file_name());
        }
    }
    Ok(())
}

fn read_username() -> Result<String, SnedError> {
    let server = get_cur_server()?;
    fs::read_to_string(get_server_path(USERNAME_PATH)?)
        .map_err(|_| SnedError::FileReadError(Some(server)))
}

fn read_secret_key() -> Result<box_::SecretKey, SnedError> {
    let server = get_cur_server()?;
    let key_bytes = fs::read(get_server_path(SECRET_KEY_PATH)?)
        .map_err(|_| SnedError::FileReadError(Some(server)))?;

    if let Some(parsed_key) = box_::SecretKey::from_slice(&key_bytes) {
        Ok(parsed_key)
    } else {
        Err(SnedError::AsymmetricKeyParseError)
    }
}

fn read_public_key() -> Result<box_::PublicKey, SnedError> {
    let server = get_cur_server()?;
    let key_bytes = fs::read(get_server_path(PUBLIC_KEY_PATH)?)
        .map_err(|_| SnedError::FileReadError(Some(server)))?;

    if let Some(parsed_key) = box_::PublicKey::from_slice(&key_bytes) {
        Ok(parsed_key)
    } else {
        Err(SnedError::AsymmetricKeyParseError)
    }
}

fn read_signing_secret_key() -> Result<sign::SecretKey, SnedError> {
    let server = get_cur_server()?;
    let key_bytes = fs::read(get_server_path(SIGNING_SECRET_KEY_PATH)?)
        .map_err(|_| SnedError::FileReadError(Some(server)))?;

    if let Some(parsed_key) = sign::SecretKey::from_slice(&key_bytes) {
        Ok(parsed_key)
    } else {
        Err(SnedError::AsymmetricKeyParseError)
    }
}

fn whoami() -> Result<(), SnedError> {
    println!(
        "Your username is {} on server {}",
        read_username()?,
        get_cur_server()?
    );
    println!("Your public key is: {}", base64_encode(&read_public_key()?));
    Ok(())
}

fn get_authenticator() -> Result<String, SnedError> {
    let response = generate_http_client()
        .get(get_cur_server_url()? + AUTHENTICATOR_URL)
        .send();
    let resp_result = generate_response_result(response)?;
    Ok(resp_result.text().unwrap_or("".to_string()))
}

fn get_signed_authenticator() -> Result<String, SnedError> {
    let authenticator = get_authenticator()?;
    let secret_key = read_signing_secret_key()?;
    let signed_authenticator = sign::sign(authenticator.as_bytes(), &secret_key);
    Ok(base64_encode(&signed_authenticator))
}

fn get_public_key(username: &str) -> Result<box_::PublicKey, SnedError> {
    let request = LookupRequestPayload {
        username: username.to_string(),
    };
    let serde_str = serde_json::to_string(&request).unwrap();
    let response = make_json_post_request(LOOKUP_URL, &serde_str)?;
    let public_key_string = response.text().unwrap_or("".to_string());
    let decoded_public_key =
        base64_decode(&public_key_string).map_err(|_| SnedError::OtherPublicKeyParseError)?;
    if let Some(key) = box_::PublicKey::from_slice(&decoded_public_key) {
        Ok(key)
    } else {
        Err(SnedError::OtherPublicKeyParseError)
    }
}

fn lookup(username: String) -> Result<(), SnedError> {
    let public_key = get_public_key(&username)?;
    println!("{}", base64_encode(&public_key));
    Ok(())
}

fn retrieve_inbox() -> Result<InboxItemList, SnedError> {
    let username = read_username()?;
    let request = InboxRequestPayload {
        username,
        signed_authenticator: get_signed_authenticator()?,
    };

    let serde_str = serde_json::to_string(&request).unwrap();
    let response = make_json_post_request(INBOX_URL, &serde_str)?;

    let resp_json: InboxItemList = response
        .json()
        .unwrap_or(InboxItemList { items: Vec::new() });
    Ok(resp_json)
}

fn inbox() -> Result<(), SnedError> {
    let resp_json = retrieve_inbox()?;

    if resp_json.items.len() == 0 {
        println!("You have no pending downloads");
        return Ok(());
    }

    let mut table = Table::new();
    table.add_row(row!["ID", "TIMESTAMP", "SENDER", "NAME", "SIZE"]);

    for item in resp_json.items.iter() {
        let plaintext_len = calculate_plaintext_len(item.file_size);
        table.add_row(row![
            &item.download_id,
            &item.date_created,
            &item.sender,
            &item.file_name,
            format_file_size(plaintext_len)
        ]);
    }
    table.printstd();
    Ok(())
}

fn list_users() -> Result<(), SnedError> {
    let username = read_username()?;
    let request = ListUsersRequestPayload {
        username,
        signed_authenticator: get_signed_authenticator()?,
    };

    let serde_str = serde_json::to_string(&request).unwrap();
    let response = make_json_post_request(LIST_USERS_URL, &serde_str)?;
    println!("{}", response.text().unwrap_or("".to_string()));
    Ok(())
}

fn write_config_files(
    username: &str,
    secret_key: &[u8],
    public_key: &[u8],
    signing_secret_key: &[u8],
    signing_public_key: &[u8],
) -> Result<(), SnedError> {
    write_server_config_file(USERNAME_PATH, username.as_bytes())?;
    write_server_config_file(SECRET_KEY_PATH, secret_key)?;
    write_server_config_file(PUBLIC_KEY_PATH, public_key)?;
    write_server_config_file(SIGNING_SECRET_KEY_PATH, signing_secret_key)?;
    write_server_config_file(SIGNING_PUBLIC_KEY_PATH, signing_public_key)?;
    Ok(())
}

fn register(username: String, server: String) -> Result<(), SnedError> {
    if does_server_config_directory_exist(&server)? {
        return Err(SnedError::AlreadyRegisteredError);
    }

    let (pub_key, sec_key) = box_::gen_keypair();
    let (signing_pub_key, signing_sec_key) = sign::gen_keypair();

    let request = RegisterRequestPayload {
        username: username.clone(),
        public_key: base64_encode(&pub_key),
        signing_public_key: base64_encode(&signing_pub_key),
    };

    let serde_str = serde_json::to_string(&request).unwrap();

    let old_server_result = get_cur_server();
    let old_server: Option<String>;
    if old_server_result.is_err() {
        old_server = None;
    } else {
        old_server = Some(old_server_result.unwrap());
    }

    set_cur_server(&server)?;
    make_json_post_request(REGISTER_URL, &serde_str)?;

    create_server_config_directory(&server)?;

    let file_write_result = write_config_files(
        &username,
        &sec_key.as_ref(),
        &pub_key.as_ref(),
        &signing_sec_key.as_ref(),
        &signing_pub_key.as_ref(),
    );

    if file_write_result.is_err() {
        force_delete_server_config_directory(&server);
        set_cur_server(&old_server.unwrap_or("".to_string())).unwrap();
    }

    file_write_result?;

    println!(
        "Registered with username {} on server {}",
        &username, &server
    );

    Ok(())
}

fn decrypt_symmetric_key(
    sender_public_key: box_::PublicKey,
    secret_key: box_::SecretKey,
    nonce: &str,
    key: &str,
    header: &str,
) -> Result<(Key, Header), ()> {
    let decoded_key = base64_decode(key)?;
    let decoded_nonce = base64_decode(nonce)?;
    let decoded_header = base64_decode(header)?;
    let nonce = box_::Nonce::from_slice(&decoded_nonce);

    if nonce.is_none() {
        return Err(());
    }

    let decrypted_key = Key::from_slice(&box_::open(
        &decoded_key,
        &nonce.unwrap(),
        &sender_public_key,
        &secret_key,
    )?);

    if decrypted_key.is_none() {
        return Err(());
    }

    let header = Header::from_slice(decoded_header.as_slice());

    if header.is_none() {
        return Err(());
    }

    Ok((decrypted_key.unwrap(), header.unwrap()))
}

fn write_response_to_writer<W: Write>(
    response: &mut Response,
    writer: &mut W,
) -> Result<(), Box<dyn std::error::Error>> {
    response.copy_to(writer)?;
    writer.flush()?;
    Ok(())
}

fn download(id: String, file_path: PathBuf) -> Result<(), SnedError> {
    let file = std::fs::File::create(&file_path)
        .map_err(|_| SnedError::FileCreateError(file_path.to_string_lossy().to_string()))?;
    let username = read_username()?;
    let secret_key = read_secret_key()?;
    let inbox = retrieve_inbox()?;
    let inbox_item: Vec<&InboxItem> = inbox
        .items
        .iter()
        .filter(|item| item.download_id == id)
        .collect();

    if inbox_item.len() == 0 {
        return Err(SnedError::ItemDoesNotExistError(id));
    }

    let inbox_item = inbox_item[0].clone();

    let sender_public_key = get_public_key(&inbox_item.sender)?;
    let (decrypted_key, header) = decrypt_symmetric_key(
        sender_public_key,
        secret_key,
        &inbox_item.shared_nonce,
        &inbox_item.shared_key,
        &inbox_item.shared_header,
    )
    .map_err(|_| SnedError::SymmetricKeyParseError)?;

    let request = DownloadRequestPayload {
        username,
        download_id: inbox_item.download_id.to_string(),
        signed_authenticator: get_signed_authenticator()?,
    };

    let plaintext_len = calculate_plaintext_len(inbox_item.file_size);

    let dec_stream = Stream::init_pull(&header, &decrypted_key)
        .map_err(|_| SnedError::AsymmetricKeyParseError)?;
    let mut writer = DecryptionWriter::new(file, dec_stream, plaintext_len);

    let serde_str = serde_json::to_string(&request).unwrap();
    let mut response = make_json_post_request(DOWNLOAD_URL, &serde_str)?;

    write_response_to_writer(&mut response, &mut writer).unwrap_or_else(|_| {
        fs::remove_file(&file_path).unwrap();
        println!("Error downloading/decrypting file");
    });

    println!(
        "\nFile written to {}",
        file_path.to_string_lossy().to_string()
    );

    Ok(())
}

fn base64_encode<T: AsRef<[u8]>>(bytes: &T) -> String {
    base64::encode(bytes, base64::Variant::Original)
}

fn base64_decode(encoded: &str) -> Result<Vec<u8>, ()> {
    base64::decode(encoded, base64::Variant::Original)
}

fn calculate_ciphertext_len(plaintext_len: u64) -> u64 {
    let num_chunks = plaintext_len as f64 / PLAINTEXT_CHUNK_LEN as f64;
    plaintext_len + num_chunks.ceil() as u64 * ABYTES as u64
}

fn calculate_plaintext_len(ciphertext_len: u64) -> u64 {
    let num_full_chunks = ciphertext_len / CIPHERTEXT_CHUNK_LEN as u64;
    num_full_chunks * PLAINTEXT_CHUNK_LEN as u64 + ciphertext_len
        - num_full_chunks * CIPHERTEXT_CHUNK_LEN as u64
        - ABYTES as u64
}

fn format_file_size(file_size: u64) -> String {
    const KB_SIZE: f64 = 1_000f64;
    const MB_SIZE: f64 = 1_000_000f64;
    const GB_SIZE: f64 = 1_000_000_000f64;
    const TB_SIZE: f64 = 1_000_000_000_000f64;

    let mut file_size = file_size as f64;

    let symbol;
    if file_size < KB_SIZE {
        return file_size.to_string() + "B";
    } else if file_size < MB_SIZE {
        symbol = "kB";
        file_size /= KB_SIZE;
    } else if file_size < GB_SIZE {
        symbol = "MB";
        file_size /= MB_SIZE;
    } else if file_size < TB_SIZE {
        symbol = "GB";
        file_size /= GB_SIZE;
    } else {
        symbol = "TB";
        file_size /= TB_SIZE;
    }

    NumberFormat::new().format(".3s", file_size) + symbol
}

fn transfer(
    file_path: PathBuf,
    recipients: Vec<String>,
    name: Option<String>,
) -> Result<(), SnedError> {
    if recipients.len() == 0 {
        println!("Expected at least one recipient as an argument");
        return Ok(());
    }

    let file = std::fs::File::open(&file_path)
        .map_err(|_| SnedError::FileOpenError(file_path.to_string_lossy().to_string()))?;
    let secret_key = read_secret_key()?;
    let metadata = file
        .metadata()
        .map_err(|_| SnedError::FileOpenError(file_path.to_string_lossy().to_string()))?;

    let key = gen_key();
    let (enc_stream, header) = Stream::init_push(&key).unwrap();

    let nonce = box_::gen_nonce();

    let mut encrypted_keys = Vec::new();
    for recipient in &recipients {
        let recipient_public_key = get_public_key(&recipient)?;
        let key = box_::seal(&key.as_ref(), &nonce, &recipient_public_key, &secret_key);
        encrypted_keys.push(base64_encode(&key));
    }

    let ciphertext_len = calculate_ciphertext_len(metadata.len());

    let request = TransferRequestPayload {
        sender: read_username()?,
        recipients,
        name: name.unwrap_or("".to_string()),
        signed_authenticator: get_signed_authenticator()?,
        shared_keys: encrypted_keys,
        shared_header: base64_encode(&header),
        shared_nonce: base64_encode(&nonce),
        data_len: ciphertext_len,
    };

    let metadata_str = serde_json::to_string(&request).unwrap();

    let mut metadata_vec: Vec<u8> = Vec::new();
    metadata_vec.append(&mut metadata_str.len().to_be_bytes().to_vec());
    metadata_vec.append(&mut metadata_str.as_bytes().to_vec());

    let reader1 = Cursor::new(metadata_vec);
    let reader2 = EncryptionReader::new(file, enc_stream, ciphertext_len);

    let chained_reader = reader1.chain(reader2);

    let response = generate_http_client()
        .post(get_cur_server_url()? + TRANSFER_URL)
        .body(reqwest::blocking::Body::new(chained_reader))
        .send();

    generate_response_result(response)?;
    println!("\nTransfer complete");

    Ok(())
}

fn main() {
    sodiumoxide::init().unwrap();

    let args = Sned::from_args();
    let cli_result = match args {
        Sned::Whoami => whoami(),
        Sned::Inbox => inbox(),
        Sned::Lookup { username } => lookup(username),
        Sned::Register { username, server } => register(username, server),
        Sned::Transfer {
            file,
            recipients,
            name,
        } => transfer(file, recipients, name),
        Sned::Download { id, file } => download(id, file),
        Sned::ChServer { server } => switch_servers(server),
        Sned::ListServers {} => list_servers(),
        Sned::ListUsers {} => list_users(),
    };

    if cli_result.is_err() {
        println!("{}", cli_result.unwrap_err());
    }
}
