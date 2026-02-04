//! Simple HTTP CONNECT proxy with host allowlist.

use crate::policy::ProxyPolicy;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

const MAX_HEADER_BYTES: usize = 8192;

#[derive(Debug)]
pub struct ProxyHandle {
    socket_path: Option<String>,
    #[allow(dead_code)]
    http_addr: Option<SocketAddr>,
    join: JoinHandle<()>,
}

impl ProxyHandle {
    /// Start the proxy with the default bind address from policy.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub async fn start(policy: &ProxyPolicy) -> Result<Self> {
        Self::start_with_bind_addr(policy, None).await
    }

    /// Start the proxy with an optional override bind address.
    ///
    /// If `bind_addr` is provided, it overrides `policy.http_addr` and the proxy
    /// binds to that address (used for network namespace veth interface).
    /// If `bind_addr` is None, falls back to policy settings.
    pub async fn start_with_bind_addr(
        policy: &ProxyPolicy,
        bind_addr: Option<SocketAddr>,
    ) -> Result<Self> {
        let allow_hosts = Arc::new(
            policy
                .allow_hosts
                .iter()
                .map(|host| host.trim().to_ascii_lowercase())
                .filter(|host| !host.is_empty())
                .collect::<Vec<_>>(),
        );

        // Use override bind_addr or fall back to policy http_addr
        let http_addr = bind_addr.or(policy.http_addr);

        if let Some(http_addr) = http_addr {
            // Only enforce loopback restriction when not using network namespace override
            if bind_addr.is_none() && !http_addr.ip().is_loopback() {
                return Err(miette::miette!(
                    "Proxy http_addr must be loopback-only: {http_addr}"
                ));
            }
            let listener = TcpListener::bind(http_addr).await.into_diagnostic()?;
            let local_addr = listener.local_addr().into_diagnostic()?;
            info!(addr = %local_addr, "Proxy listening (tcp)");

            let join = tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _addr)) => {
                            let allow_hosts = allow_hosts.clone();
                            tokio::spawn(async move {
                                if let Err(err) = handle_tcp_connection(stream, allow_hosts).await {
                                    warn!(error = %err, "Proxy connection error");
                                }
                            });
                        }
                        Err(err) => {
                            warn!(error = %err, "Proxy accept error");
                            break;
                        }
                    }
                }
            });

            return Ok(Self {
                socket_path: None,
                http_addr: Some(local_addr),
                join,
            });
        }

        let socket_path = policy
            .unix_socket
            .as_ref()
            .ok_or_else(|| miette::miette!("Proxy policy must set http_addr or unix_socket"))?
            .to_string_lossy()
            .to_string();

        ensure_socket_dir(&socket_path)?;
        cleanup_socket(&socket_path).await?;

        let listener = UnixListener::bind(&socket_path).into_diagnostic()?;
        info!(socket = %socket_path, "Proxy listening (unix)");

        let join = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let allow_hosts = allow_hosts.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_unix_connection(stream, allow_hosts).await {
                                warn!(error = %err, "Proxy connection error");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, "Proxy accept error");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            socket_path: Some(socket_path),
            http_addr: None,
            join,
        })
    }

    #[allow(dead_code)]
    pub const fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.join.abort();
        if let Some(path) = self.socket_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn ensure_socket_dir(socket_path: &str) -> Result<()> {
    let parent = Path::new(socket_path).parent().ok_or_else(|| {
        miette::miette!("Proxy socket path has no parent directory: {socket_path}")
    })?;
    std::fs::create_dir_all(parent).into_diagnostic()?;
    Ok(())
}

async fn cleanup_socket(socket_path: &str) -> Result<()> {
    if tokio::fs::try_exists(socket_path).await.into_diagnostic()? {
        tokio::fs::remove_file(socket_path)
            .await
            .into_diagnostic()?;
    }
    Ok(())
}

async fn handle_unix_connection(
    mut client: UnixStream,
    allow_hosts: Arc<Vec<String>>,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_HEADER_BYTES];
    let mut used = 0usize;

    loop {
        if used == buf.len() {
            respond_unix(
                &mut client,
                b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n",
            )
            .await?;
            return Ok(());
        }

        let n = client.read(&mut buf[used..]).await.into_diagnostic()?;
        if n == 0 {
            return Ok(());
        }
        used += n;

        if buf[..used].windows(4).any(|win| win == b"\r\n\r\n") {
            break;
        }
    }

    let request = String::from_utf8_lossy(&buf[..used]);
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method != "CONNECT" {
        respond_unix(&mut client, b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
        return Ok(());
    }

    let (host, port) = parse_target(target)?;
    let host_lc = host.to_ascii_lowercase();

    if !is_allowed(&host_lc, &allow_hosts) {
        info!(host = %host_lc, port, "Proxy denied host");
        respond_unix(&mut client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        return Ok(());
    }

    info!(host = %host_lc, port, "Proxy allowed host");
    let mut upstream = TcpStream::connect((host.as_str(), port))
        .await
        .into_diagnostic()?;

    respond_unix(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    debug!(host = %host, port, "Proxy tunnel established");
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .into_diagnostic()?;

    Ok(())
}

async fn handle_tcp_connection(mut client: TcpStream, allow_hosts: Arc<Vec<String>>) -> Result<()> {
    let mut buf = vec![0u8; MAX_HEADER_BYTES];
    let mut used = 0usize;

    loop {
        if used == buf.len() {
            respond_tcp(
                &mut client,
                b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n",
            )
            .await?;
            return Ok(());
        }

        let n = client.read(&mut buf[used..]).await.into_diagnostic()?;
        if n == 0 {
            return Ok(());
        }
        used += n;

        if buf[..used].windows(4).any(|win| win == b"\r\n\r\n") {
            break;
        }
    }

    let request = String::from_utf8_lossy(&buf[..used]);
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method != "CONNECT" {
        respond_tcp(&mut client, b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
        return Ok(());
    }

    let (host, port) = parse_target(target)?;
    let host_lc = host.to_ascii_lowercase();

    if !is_allowed(&host_lc, &allow_hosts) {
        info!(host = %host_lc, port, "Proxy denied host");
        respond_tcp(&mut client, b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        return Ok(());
    }

    info!(host = %host_lc, port, "Proxy allowed host");
    let mut upstream = TcpStream::connect((host.as_str(), port))
        .await
        .into_diagnostic()?;

    respond_tcp(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    debug!(host = %host, port, "Proxy tunnel established");
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .into_diagnostic()?;

    Ok(())
}

fn parse_target(target: &str) -> Result<(String, u16)> {
    let (host, port_str) = target
        .split_once(':')
        .ok_or_else(|| miette::miette!("CONNECT target missing port: {target}"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| miette::miette!("Invalid port in CONNECT target: {target}"))?;
    Ok((host.to_string(), port))
}

fn is_allowed(host: &str, allow_hosts: &[String]) -> bool {
    if allow_hosts.is_empty() {
        return true;
    }

    for entry in allow_hosts {
        if entry.starts_with('.') {
            if host.ends_with(entry) {
                return true;
            }
            continue;
        }

        if host == entry {
            return true;
        }

        let suffix = format!(".{entry}");
        if host.ends_with(&suffix) {
            return true;
        }
    }

    false
}

async fn respond_unix(client: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    client.write_all(bytes).await.into_diagnostic()?;
    Ok(())
}

async fn respond_tcp(client: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    client.write_all(bytes).await.into_diagnostic()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::ProxyHandle;
    use super::is_allowed;
    #[cfg(target_os = "linux")]
    use crate::policy::ProxyPolicy;
    #[cfg(target_os = "linux")]
    use std::net::SocketAddr;
    #[cfg(target_os = "linux")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(target_os = "linux")]
    use tokio::net::{TcpListener, TcpStream};
    #[cfg(target_os = "linux")]
    use tokio::time::{Duration, sleep};

    #[cfg(target_os = "linux")]
    fn temp_socket_addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    #[cfg(target_os = "linux")]
    async fn connect_with_retry(addr: SocketAddr) -> TcpStream {
        let mut attempts = 0;
        loop {
            match TcpStream::connect(addr).await {
                Ok(stream) => return stream,
                Err(err) if attempts < 20 => {
                    attempts += 1;
                    let _ = err;
                    sleep(Duration::from_millis(10)).await;
                }
                Err(err) => panic!("Failed to connect to proxy socket: {err}"),
            }
        }
    }

    #[test]
    fn allowlist_matches_expected_hosts() {
        let allow_hosts = vec![
            "api.anthropic.com".to_string(),
            ".openai.com".to_string(),
            "example.com".to_string(),
        ];

        assert!(is_allowed("api.anthropic.com", &allow_hosts));
        assert!(is_allowed("sub.openai.com", &allow_hosts));
        assert!(is_allowed("example.com", &allow_hosts));
        assert!(is_allowed("foo.example.com", &allow_hosts));
        assert!(!is_allowed("openai.com", &allow_hosts));
        assert!(!is_allowed("google.com", &allow_hosts));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn proxy_denies_disallowed_host() {
        let policy = ProxyPolicy {
            unix_socket: None,
            http_addr: Some(temp_socket_addr()),
            allow_hosts: vec!["localhost".to_string()],
        };

        let proxy = ProxyHandle::start(&policy).await.unwrap();
        let addr = proxy.http_addr().expect("missing http addr");
        let mut stream = connect_with_retry(addr).await;

        stream
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let mut response = [0u8; 128];
        let n = stream.read(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response[..n]);
        assert!(text.contains("403"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn proxy_allows_allowed_host() {
        let policy = ProxyPolicy {
            unix_socket: None,
            http_addr: Some(temp_socket_addr()),
            allow_hosts: vec!["localhost".to_string()],
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        let proxy = ProxyHandle::start(&policy).await.unwrap();
        let addr = proxy.http_addr().expect("missing http addr");
        let mut stream = connect_with_retry(addr).await;

        let request = format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut response = [0u8; 128];
        let n = stream.read(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response[..n]);
        assert!(text.contains("200"));

        accept_task.await.unwrap();
    }
}
