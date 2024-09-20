use clap::Parser;
use cli_clipboard::{ClipboardContext, ClipboardProvider};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io;
use std::mem;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tokio_native_tls::native_tls::Identity;

// 配置结构体
#[derive(Debug, Deserialize, Serialize)]
struct Config {
    unique_name: String,
    is_server: bool,
    server_address: String,
    server_port: u16,
    ssl_key: String,
}

// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 配置文件路径
    #[arg(long)]
    config: String,
    /// 手动复制字符串到服务器
    #[arg(long)]
    copy: Option<String>,
    /// 手动从服务器粘贴字符串
    #[arg(long)]
    paste: bool,
    /// 自动同步服务器数据
    #[arg(long)]
    sync: bool,
}

// 命令枚举
enum Cmd {
    Copy,
    Paste,
    Sync,
    Invalid,
}

impl Cmd {
    fn to_u32(&self) -> u32 {
        match self {
            Cmd::Copy => 0,
            Cmd::Paste => 1,
            Cmd::Sync => 2,
            Cmd::Invalid => u32::MAX,
        }
    }

    fn from_u32(i: u32) -> Self {
        match i {
            0 => Cmd::Copy,
            1 => Cmd::Paste,
            2 => Cmd::Sync,
            _ => Cmd::Invalid,
        }
    }
}

// 消息头结构体
#[derive(Debug, Serialize, Deserialize)]
#[repr(C, packed)]
struct MsgHeader {
    header: u32,
    cmd: u32,
    length: u64,
}

// 服务器端处理函数
async fn server(config: &Config) -> Result<(), Box<dyn Error>> {
    let addr = format!("{}:{}", config.server_address, config.server_port);
    let tcp: TcpListener = TcpListener::bind(&addr).await?;

    let identity = std::fs::read(&config.ssl_key)?;
    let cert = Identity::from_pkcs12(&identity, "")?;
    let tls_acceptor = tokio_native_tls::TlsAcceptor::from(
        tokio_native_tls::native_tls::TlsAcceptor::builder(cert).build()?,
    );
    let global_cache = Arc::new(Mutex::new(Vec::new()));
    let (tx, _) = broadcast::channel(16);

    loop {
        let (socket, _) = tcp.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let global_cache = global_cache.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            // 处理TLS连接
            let mut tls_stream = match tls_acceptor.accept(socket).await {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("TLS 接受错误: {}", e);
                    return;
                }
            };

            // 读取消息头
            let mut buf = [0u8; mem::size_of::<MsgHeader>()];
            let n = match tls_stream.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("读取头部失败: {}", e);
                    return;
                }
            };

            if n == 0 {
                return;
            }

            // 反序列化消息头
            let msg: MsgHeader = match bincode::deserialize(&buf) {
                Ok(msg) => msg,
                Err(e) => {
                    eprintln!("反序列化头部失败: {}", e);
                    return;
                }
            };
            if msg.header != 0xdeadbeaf {
                eprintln!("无效的消息头");
                return;
            }

            // 处理不同命令
            match Cmd::from_u32(msg.cmd) {
                Cmd::Copy => {
                    let mut data: Vec<u8> = vec![0; msg.length as usize];
                    if let Err(e) = tls_stream.read_exact(&mut data).await {
                        eprintln!("读取数据失败: {}", e);
                        return;
                    }
                    let mut global = global_cache.lock().await;
                    *global = data;
                    if tx.receiver_count() != 0 {
                        let _ = tx.send(1);
                    }
                }
                Cmd::Paste => {
                    let global = global_cache.lock().await;
                    if let Err(e) = tls_stream.write_all(&global).await {
                        eprintln!("写入数据失败: {}", e);
                    }
                }
                Cmd::Sync => {
                    let mut rx = tx.subscribe();

                    loop {
                        match rx.recv().await {
                            Ok(_) => {
                                let global = global_cache.lock().await;
                                let msg_header = MsgHeader {
                                    header: 0xdeadbeaf,
                                    cmd: Cmd::Sync.to_u32(),
                                    length: global.len() as u64,
                                };
                                let encoded = match bincode::serialize(&msg_header) {
                                    Ok(data) => data,
                                    Err(e) => {
                                        eprintln!("序列化头部失败: {}", e);
                                        break;
                                    }
                                };
                                if let Err(e) = tls_stream.write_all(&encoded).await {
                                    eprintln!("同步头部失败: {}", e);
                                    break;
                                }
                                if let Err(e) = tls_stream.write_all(&global).await {
                                    eprintln!("同步消息失败: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("广播接收失败: {}", e);
                                break;
                            }
                        }
                    }
                }
                Cmd::Invalid => {
                    eprintln!("无效的命令");
                }
            }
        });
    }
}

// 客户端连接和TLS安全化函数
async fn connect_and_secure(
    addr: &str,
    config: &Config,
) -> Result<tokio_native_tls::TlsStream<TcpStream>, Box<dyn Error>> {
    let socket = TcpStream::connect(addr).await?;
    let mut native_tls_builder = tokio_native_tls::native_tls::TlsConnector::builder();
    native_tls_builder.danger_accept_invalid_certs(true);
    let cx = native_tls_builder.build()?;
    let cx = tokio_native_tls::TlsConnector::from(cx);
    let stream = cx.connect(config.server_address.as_str(), socket).await?;
    Ok(stream)
}

// 客户端处理函数
async fn client(config: &Config, cmd: Cmd, msg: Option<String>) -> Result<String, Box<dyn Error>> {
    let addr = format!("{}:{}", config.server_address, config.server_port);
    let mut stream = match connect_and_secure(&addr, config).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("连接失败: {}", e);
            return Err(e);
        }
    };

    match cmd {
        Cmd::Copy => {
            if let Some(data) = msg {
                let data_bytes = data.as_bytes();
                let msg_header = MsgHeader {
                    header: 0xdeadbeaf,
                    cmd: cmd.to_u32(),
                    length: data_bytes.len() as u64,
                };
                let mut encoded = bincode::serialize(&msg_header)?;
                encoded.extend_from_slice(data_bytes);

                if let Err(e) = stream.write_all(&encoded).await {
                    eprintln!("发送数据失败: {}", e);
                    return Err(Box::new(e));
                }
            }
        }
        Cmd::Paste => {
            let msg_header = MsgHeader {
                header: 0xdeadbeaf,
                cmd: cmd.to_u32(),
                length: 0,
            };
            let encoded = bincode::serialize(&msg_header)?;
            if let Err(e) = stream.write_all(&encoded).await {
                eprintln!("发送头部失败: {}", e);
                return Err(Box::new(e));
            }

            let mut data_recv = Vec::new();
            match timeout(Duration::from_secs(10), stream.read_to_end(&mut data_recv)).await {
                Ok(Ok(_)) => {
                    let data = String::from_utf8(data_recv).unwrap_or_default();
                    println!("{}", data);
                    if !data.is_empty() {
                        let mut ctx = match ClipboardContext::new() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("剪贴板初始化失败: {}", e);
                                return Ok(String::new());
                            }
                        };
                        if let Err(e) = ctx.set_contents(data) {
                            eprintln!("设置剪贴板内容失败: {}", e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("读取数据失败: {}", e);
                }
                Err(_) => {
                    eprintln!("读取数据超时");
                }
            }
        }
        Cmd::Sync => {
            let msg_header = MsgHeader {
                header: 0xdeadbeaf,
                cmd: cmd.to_u32(),
                length: 0,
            };
            let encoded = bincode::serialize(&msg_header)?;
            if let Err(e) = stream.write_all(&encoded).await {
                eprintln!("发送同步命令失败: {}", e);
                return Err(Box::new(e));
            }

            loop {
                match timeout(Duration::from_secs(10), async {
                    let mut header_buf = [0u8; mem::size_of::<MsgHeader>()];
                    match stream.read_exact(&mut header_buf).await {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("读取头部失败: {}", e);
                            return Err(e);
                        }
                    }

                    let msg: MsgHeader = match bincode::deserialize(&header_buf) {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("反序列化头部失败: {}", e);
                            return Err(io::Error::new(io::ErrorKind::Other, "反序列化失败"));
                        }
                    };

                    if msg.header != 0xdeadbeaf {
                        eprintln!("同步数据错误，头部不匹配！");
                        return Err(io::Error::new(io::ErrorKind::Other, "头部不匹配"));
                    }
                    if msg.cmd != Cmd::Sync.to_u32() {
                        eprintln!("同步数据错误，命令不匹配！");
                        return Err(io::Error::new(io::ErrorKind::Other, "命令不匹配"));
                    }

                    let mut data_buf = vec![0u8; msg.length as usize];
                    match stream.read_exact(&mut data_buf).await {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("读取同步数据失败: {}", e);
                            return Err(e);
                        }
                    }

                    let data = match String::from_utf8(data_buf) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("UTF-8 解析失败: {}", e);
                            return Err(io::Error::new(io::ErrorKind::Other, "UTF-8 解析失败"));
                        }
                    };

                    let mut ctx = match ClipboardContext::new() {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("剪贴板初始化失败: {}", e);
                            return Err(io::Error::new(io::ErrorKind::Other, "剪贴板初始化失败"));
                        }
                    };
                    if let Err(e) = ctx.set_contents(data) {
                        eprintln!("设置剪贴板内容失败: {}", e);
                    }
                    Ok(())
                })
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        eprintln!("同步过程中发生错误: {}", e);
                        // 尝试重新连接
                        loop {
                            eprintln!("尝试重新连接...");
                            match connect_and_secure(&addr, config).await {
                                Ok(new_stream) => {
                                    stream = new_stream;
                                    // 重新发送同步命令
                                    if let Err(e) = stream.write_all(&encoded).await {
                                        eprintln!("重新发送同步命令失败: {}", e);
                                        continue;
                                    }
                                    break;
                                }
                                Err(e) => {
                                    eprintln!("重新连接失败: {}", e);
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                    continue;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        eprintln!("同步命令超时，尝试重新连接...");
                        // 尝试重新连接
                        loop {
                            eprintln!("尝试重新连接...");
                            match connect_and_secure(&addr, config).await {
                                Ok(new_stream) => {
                                    stream = new_stream;
                                    // 重新发送同步命令
                                    if let Err(e) = stream.write_all(&encoded).await {
                                        eprintln!("重新发送同步命令失败: {}", e);
                                        continue;
                                    }
                                    break;
                                }
                                Err(e) => {
                                    eprintln!("重新连接失败: {}", e);
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {
            eprintln!("未实现的命令！");
        }
    }

    Ok(String::from(""))
}

// 主要功能：客户端或服务器入口
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 解析命令行参数
    let cli = Args::parse();

    // 读取配置文件
    let config_file = File::open(&cli.config)?;
    let config: Config = serde_yaml::from_reader(config_file)?;

    if config.is_server {
        // 运行服务器
        server(&config).await?;
    } else {
        // 运行客户端
        // 创建一个可变的客户端函数，以便后续重连时更新流
        if cli.sync {
            if let Err(e) = client(&config, Cmd::Sync, None).await {
                eprintln!("同步命令失败: {}", e);
            }
        }
        if cli.paste {
            if let Err(e) = client(&config, Cmd::Paste, None).await {
                eprintln!("粘贴命令失败: {}", e);
            }
        }
        if let Some(data) = cli.copy {
            if let Err(e) = client(&config, Cmd::Copy, Some(data)).await {
                eprintln!("复制命令失败: {}", e);
            }
        }
    }
    Ok(())
}
