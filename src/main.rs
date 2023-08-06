use clap::Parser;
use cli_clipboard::{ClipboardContext, ClipboardProvider};
use serde::Deserialize;
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::mem;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_native_tls::native_tls::Identity;

#[derive(Debug, Deserialize, Serialize)]
struct Config {
    unique_name: String,
    is_server: bool,
    server_address: String,
    server_port: u16,
    ssl_key: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// the path of config file
    #[arg(long)]
    config: String,
    /// copy the string to server manually
    #[arg(long)]
    copy: Option<String>,
    /// paste the string from server manually
    #[arg(long)]
    paste: bool,
}

enum Cmd {
    Copy,
    Paste,
    Invalid,
}

impl Cmd {
    fn to_u32(&self) -> u32 {
        match self {
            Cmd::Copy => 0,
            Cmd::Paste => 1,
            Cmd::Invalid => u32::MAX,
        }
    }

    fn from_u32(i: u32) -> Self {
        match i {
            0 => Cmd::Copy,
            1 => Cmd::Paste,
            _ => Cmd::Invalid,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C, packed)]
struct MsgHeader {
    header: u32,
    cmd: u32,
    length: u64,
}

async fn server(config: &Config) -> Result<(), Box<dyn Error>> {
    let addr = config.server_address.clone() + ":" + config.server_port.to_string().as_str();
    let tcp: TcpListener = TcpListener::bind(&addr).await?;

    let identity = std::fs::read(&config.ssl_key)?;
    let cert = Identity::from_pkcs12(&identity, "")?;
    let tls_acceptor = tokio_native_tls::TlsAcceptor::from(
        tokio_native_tls::native_tls::TlsAcceptor::builder(cert).build()?,
    );
    let global_cache = Arc::new(Mutex::new(Vec::new()));

    loop {
        let (socket, _) = tcp.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let global_cache = global_cache.clone();
        tokio::spawn(async move {
            let mut tls_stream = tls_acceptor.accept(socket).await.expect("Accept error");

            let mut buf = [0u8; mem::size_of::<MsgHeader>()];
            let n = tls_stream
                .read(&mut buf)
                .await
                .expect("Failed to read header from socket.");

            if n == 0 {
                return;
            }

            let msg: MsgHeader = bincode::deserialize(&buf).unwrap();
            if msg.header != 0xdeadbeaf {
                return;
            }

            match Cmd::from_u32(msg.cmd) {
                Cmd::Copy => {
                    let mut data: Vec<u8> = vec![0; msg.length as usize];
                    let _n = tls_stream
                        .read(&mut data)
                        .await
                        .expect("Failed to read data from socket.");
                    let mut global = global_cache.lock().await;
                    *global = data;
                }
                Cmd::Paste => {
                    let global = global_cache.lock().await;
                    tls_stream
                        .write_all(&global.to_vec())
                        .await
                        .expect("Failed to write data back.");
                    dbg!("{}", String::from_utf8(global.to_vec()).unwrap());
                }
                _ => {
                    println!("Invalid Cmd.");
                }
            }
        });
    }
}

async fn client(config: &Config, cmd: Cmd, msg: Option<String>) -> Result<String, Box<dyn Error>> {
    let addr = config.server_address.clone() + ":" + config.server_port.to_string().as_str();

    match cmd {
        Cmd::Copy => {
            let data = msg.unwrap();
            let data = data.as_bytes();
            let msg_header: MsgHeader = MsgHeader {
                header: 0xdeadbeaf,
                cmd: cmd.to_u32(),
                length: data.len() as u64,
            };
            let mut encoded: Vec<u8> = bincode::serialize(&msg_header)?;
            encoded.extend_from_slice(data);

            let socket = TcpStream::connect(&addr).await?;
            let mut native_tls_builder = tokio_native_tls::native_tls::TlsConnector::builder();
            native_tls_builder.danger_accept_invalid_certs(true);
            let cx = native_tls_builder.build()?;
            let cx = tokio_native_tls::TlsConnector::from(cx);

            let mut stream = cx.connect(config.server_address.as_str(), socket).await?;
            stream.write_all(&encoded).await?;
        }
        Cmd::Paste => {
            let msg_header: MsgHeader = MsgHeader {
                header: 0xdeadbeaf,
                cmd: cmd.to_u32(),
                length: 0,
            };
            let encoded: Vec<u8> = bincode::serialize(&msg_header)?;

            let socket = TcpStream::connect(&addr).await?;
            let mut native_tls_builder = tokio_native_tls::native_tls::TlsConnector::builder();
            native_tls_builder.danger_accept_invalid_certs(true);
            let cx = native_tls_builder.build()?;
            let cx = tokio_native_tls::TlsConnector::from(cx);

            let mut stream = cx.connect(config.server_address.as_str(), socket).await?;
            stream.write_all(&encoded).await?;

            let mut data_recv: Vec<u8> = Vec::new();
            stream.read_to_end(&mut data_recv).await?;

            if !data_recv.is_empty() {
                let mut ctx = ClipboardContext::new().unwrap();
                ctx.set_contents(String::from_utf8(data_recv).unwrap())
                    .unwrap();
            }
        }
        _ => {
            println!("unreachable CMD!")
        }
    }

    Ok(String::from(""))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Read the command-line arguments
    let cli = Args::parse();

    let config_file = File::open(cli.config).unwrap();
    let config: Config = serde_yaml::from_reader(config_file)?;

    if config.is_server {
        server(&config).await?;
    } else {
        if cli.paste {
            let msg = client(&config, Cmd::Paste, None).await?;
            dbg!("{}", msg);
        }
        if let Some(data) = cli.copy {
            client(&config, Cmd::Copy, Some(data)).await?;
        }
    }
    Ok(())
}