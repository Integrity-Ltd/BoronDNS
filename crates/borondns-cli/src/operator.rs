use std::path::Path;

#[derive(Debug, PartialEq, Eq, clap::Subcommand)]
pub(crate) enum ZoneAction {
    /// Show live zone metadata and refresh status as JSON.
    Show { zone: String },
    /// Stream one active zone generation as RFC 3597 zone-file records.
    Dump { zone: String },
    /// Queue an ordinary SOA/IXFR/AXFR refresh (does not wait for completion).
    Refresh { zone: String },
    /// Queue full AXFR even with an unchanged serial (does not wait for completion).
    Retransfer { zone: String },
}

pub(crate) async fn run(socket: &Path, action: ZoneAction) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        tokio::time::timeout(
            std::time::Duration::from_secs(310),
            run_unix(socket, action),
        )
        .await
        .map_err(|_| anyhow::anyhow!("operator command timed out; any dump output is incomplete"))?
    }
    #[cfg(not(unix))]
    {
        let _ = (socket, action);
        anyhow::bail!("zone commands require Unix sockets")
    }
}

#[cfg(unix)]
async fn run_unix(socket: &Path, action: ZoneAction) -> anyhow::Result<()> {
    use anyhow::{Context, anyhow, bail};
    use std::io::Write;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let (command, zone) = match action {
        ZoneAction::Show { zone } => ("show", zone),
        ZoneAction::Dump { zone } => ("dump", zone),
        ZoneAction::Refresh { zone } => ("refresh", zone),
        ZoneAction::Retransfer { zone } => ("retransfer", zone),
    };
    let bytes = serde_json::to_vec(&serde_json::json!({"command": command, "zone": zone}))?;
    if bytes.len() > 4096 {
        bail!("operator request exceeds 4096 bytes");
    }
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to operator socket {}", socket.display()))?;
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    let mut reader = BufReader::new(stream);
    let mut header = String::new();
    (&mut reader).take(65_536).read_line(&mut header).await?;
    if !header.ends_with('\n') {
        bail!("missing or oversized operator response");
    }
    let header: serde_json::Value =
        serde_json::from_str(&header).context("invalid operator response")?;
    if header["ok"] != true {
        bail!(
            "{}",
            header["error"]
                .as_str()
                .unwrap_or("operator request failed")
        );
    }
    if command != "dump" {
        return crate::write_stdout_text(&format!(
            "{}\n",
            serde_json::to_string_pretty(&header["data"])?
        ))
        .context("writing operator response");
    }
    let expected = header["records"]
        .as_u64()
        .ok_or_else(|| anyhow!("dump response has no record count"))?;
    let mut line = Vec::new();
    for _ in 0..expected {
        line.clear();
        // Maximum RDATA is 65535 bytes, printed as hex plus an escaped owner.
        (&mut reader)
            .take(133_120)
            .read_until(b'\n', &mut line)
            .await?;
        if line.last() != Some(&b'\n') {
            bail!("zone dump truncated or oversized; discard partial output");
        }
        match std::io::stdout().write_all(&line) {
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
            result => result.context("writing zone dump")?,
        }
    }
    let mut extra = [0];
    if reader.read(&mut extra).await? != 0 {
        bail!("unexpected data after zone dump; discard output");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;
    #[cfg(unix)]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(unix)]
    #[tokio::test]
    async fn operator_client_rejects_truncated_and_oversized_responses() {
        use std::os::unix::fs::DirBuilderExt;
        let root = std::env::temp_dir().join(format!(
            "borondns-operator-client-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        for (index, response) in [
            b"{\"ok\":true,\"records\":1}\n".to_vec(),
            b"{\"ok\":true,\"records\":0}\nextra\n".to_vec(),
            vec![b'x'; 65_536],
            b"{\"ok\":false,\"error\":\"zone not found\"}\n".to_vec(),
        ]
        .into_iter()
        .enumerate()
        {
            let path = root.join(format!("{index}.sock"));
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            let peer = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u32().await.unwrap() as usize;
                assert!(length <= 4096);
                let mut request = vec![0; length];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&request).unwrap()["command"],
                    "dump"
                );
                let _ = stream.write_all(&response).await;
            });
            assert!(
                run(
                    &path,
                    ZoneAction::Dump {
                        zone: "example.test.".to_owned()
                    }
                )
                .await
                .is_err()
            );
            peer.await.unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
