//! Capability-rooted file operations for authenticated OpenGate file streams.

use std::{
    io::{Read, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::UNIX_EPOCH,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions, Permissions},
};
use opengate_protocol::{CHUNK_SIZE, FileEntry, FileReply, FileRequest, read_frame, write_frame};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

const PART_PREFIX: &str = ".opengate-upload-";

/// Serve exactly one file operation after the daemon has authorized the stream.
/// All remote paths are capability-relative to `root`; symlinks are refused.
pub async fn serve<S>(
    mut stream: S,
    root: PathBuf,
    peer: String,
    cancel: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let root =
        Dir::open_ambient_dir(root, ambient_authority()).context("opening file access root")?;
    let req: FileRequest = tokio::select! { _ = cancel.cancelled() => return Ok(()), r = read_frame(&mut stream) => r? };
    match req {
        FileRequest::Download { path, offset } => {
            download(&mut stream, &root, &path, offset, cancel).await
        }
        FileRequest::Upload {
            path,
            size,
            sha256,
            overwrite,
        } => {
            upload(
                &mut stream,
                &root,
                &peer,
                &path,
                size,
                &sha256,
                overwrite,
                cancel,
            )
            .await
        }
        other => match blocking(move || dispatch(&root, other)).await {
            Ok(reply) => write_frame(&mut stream, &reply).await,
            Err(error) => write_frame(&mut stream, &FileReply::Error(error.to_string())).await,
        },
    }
}

/// Make one non-streaming file API request. Upload and download use `push` and `pull`.
pub async fn request<S>(mut stream: S, req: FileRequest) -> Result<FileReply>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ensure!(
        !matches!(
            req,
            FileRequest::Upload { .. } | FileRequest::Download { .. }
        ),
        "use push or pull for streaming transfers"
    );
    write_frame(&mut stream, &req).await?;
    let reply = read_frame(&mut stream).await?;
    reply_result(reply)
}

/// Upload one file with SHA-256 integrity checking. The peer's `Ready` offset
/// is durable and may be used by a connection retry with the same arguments.
pub async fn push<S>(mut stream: S, source: &Path, remote: &str, overwrite: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let source = source.to_owned();
    let source_for_info = source.clone();
    let (size, hash) = blocking(move || file_info(&source_for_info)).await?;
    write_frame(
        &mut stream,
        &FileRequest::Upload {
            path: remote.into(),
            size,
            sha256: hash.clone(),
            overwrite,
        },
    )
    .await?;
    let ready = reply_result(read_frame(&mut stream).await?)?;
    let offset = match ready {
        FileReply::Ready {
            offset,
            size: remote_size,
            sha256,
        } if remote_size == size && sha256 == hash && offset <= size => offset,
        _ => bail!("invalid upload readiness reply"),
    };
    let mut file = tokio::fs::File::open(source).await?;
    tokio::io::AsyncSeekExt::seek(&mut file, SeekFrom::Start(offset)).await?;
    let mut current = offset;
    let mut buf = vec![0_u8; CHUNK_SIZE];
    while current < size {
        let read = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
        ensure!(read != 0, "source changed during upload");
        write_frame(
            &mut stream,
            &FileReply::Chunk {
                offset: current,
                data: buf[..read].to_vec(),
            },
        )
        .await?;
        current += read as u64;
    }
    write_frame(
        &mut stream,
        &FileReply::Complete {
            sha256: hash.clone(),
        },
    )
    .await?;
    match reply_result(read_frame(&mut stream).await?)? {
        FileReply::Complete { sha256 } if sha256 == hash => Ok(()),
        _ => bail!("invalid upload completion reply"),
    }
}

/// Download one file into a durable sibling `.part` file, verify it, then atomically publish it.
pub async fn pull<S>(mut stream: S, remote: &str, destination: &Path, overwrite: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    validate_local_destination(destination, overwrite)?;
    let part = part_path(destination)?;
    let state_path = download_state_path(&part);
    reject_local_symlink(&part)?;
    reject_local_symlink(&state_path)?;
    let prior_state = tokio::fs::read_to_string(&state_path).await.ok();
    let mut local_offset = tokio::fs::metadata(&part)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    if local_offset != 0 && prior_state.is_none() {
        bail!("refusing an unowned partial download; remove it manually before retrying");
    }
    write_frame(
        &mut stream,
        &FileRequest::Download {
            path: remote.into(),
            offset: local_offset,
        },
    )
    .await?;
    let ready = reply_result(read_frame(&mut stream).await?)?;
    let (offset, size, expected) = match ready {
        FileReply::Ready {
            offset,
            size,
            sha256,
        } if offset <= size => (offset, size, sha256),
        _ => bail!("invalid download readiness reply"),
    };
    ensure!(
        offset == local_offset,
        "remote rejected local partial transfer; remove the .part file and retry"
    );
    let state = download_state(remote, size, &expected);
    if let Some(prior) = prior_state {
        if prior != state {
            let _ = tokio::fs::remove_file(&part).await;
            let _ = tokio::fs::remove_file(&state_path).await;
            bail!(
                "remote file identity changed; partial transfer was discarded and may be retried"
            );
        }
    }
    write_local_durable(&state_path, state.as_bytes()).await?;
    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).write(true);
    let mut file = options.open(&part).await?;
    tokio::io::AsyncSeekExt::seek(&mut file, SeekFrom::Start(offset)).await?;
    let mut current = offset;
    loop {
        let frame: FileReply = read_frame(&mut stream).await?;
        match frame {
            FileReply::Chunk { offset, data } => {
                ensure!(
                    offset == current
                        && data.len() <= CHUNK_SIZE
                        && current + data.len() as u64 <= size,
                    "invalid download chunk"
                );
                tokio::io::AsyncWriteExt::write_all(&mut file, &data).await?;
                current += data.len() as u64;
            }
            FileReply::Complete { sha256 } => {
                ensure!(current == size && sha256 == expected, "incomplete download");
                break;
            }
            FileReply::Error(e) => bail!("remote file operation failed: {e}"),
            _ => bail!("unexpected download frame"),
        }
    }
    file.sync_all().await?;
    drop(file);
    let checked = part.clone();
    let actual = blocking(move || file_info(&checked).map(|(_, h)| h)).await?;
    ensure!(
        actual == expected,
        "download checksum mismatch; partial file retained for retry"
    );
    publish_local(&part, destination, overwrite)?;
    let _ = tokio::fs::remove_file(state_path).await;
    Ok(())
}

async fn download<S>(
    stream: &mut S,
    root: &Dir,
    raw: &str,
    offset: u64,
    cancel: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let path = checked(root, raw, false)?;
    let hash_file = root.open(&path)?.into_std();
    let (size, hash) = blocking(move || file_info_handle(hash_file)).await?;
    ensure!(offset <= size, "download offset exceeds file length");
    write_frame(
        stream,
        &FileReply::Ready {
            offset,
            size,
            sha256: hash.clone(),
        },
    )
    .await?;
    let file = root.open(&path)?.into_std();
    let mut file = tokio::fs::File::from_std(file);
    tokio::io::AsyncSeekExt::seek(&mut file, SeekFrom::Start(offset)).await?;
    let mut current = offset;
    let mut buf = vec![0_u8; CHUNK_SIZE];
    while current < size {
        let count = tokio::select! { _ = cancel.cancelled() => return Ok(()), r = tokio::io::AsyncReadExt::read(&mut file, &mut buf) => r? };
        ensure!(count != 0, "file changed during download");
        write_frame(
            stream,
            &FileReply::Chunk {
                offset: current,
                data: buf[..count].to_vec(),
            },
        )
        .await?;
        current += count as u64;
    }
    write_frame(stream, &FileReply::Complete { sha256: hash }).await
}

async fn upload<S>(
    stream: &mut S,
    root: &Dir,
    peer: &str,
    raw: &str,
    size: u64,
    expected: &str,
    overwrite: bool,
    cancel: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ensure!(
        is_hash(expected),
        "upload checksum must be a SHA-256 hex digest"
    );
    let dest = checked(root, raw, true)?;
    let identity = staging_identity(peer, &dest, size, expected);
    let stage = PathBuf::from(format!("{PART_PREFIX}{identity}.part"));
    let checkpoint = PathBuf::from(format!("{PART_PREFIX}{identity}.state"));
    let checkpoint_contents = format!(
        "peer={peer}\npath={}\nsize={size}\nsha256={expected}\n",
        dest.display()
    );
    let offset = prepare_stage(root, &stage, &checkpoint, &checkpoint_contents, size)?;
    write_frame(
        stream,
        &FileReply::Ready {
            offset,
            size,
            sha256: expected.into(),
        },
    )
    .await?;
    let file = root
        .open_with(&stage, OpenOptions::new().append(true).write(true))?
        .into_std();
    let mut file = tokio::fs::File::from_std(file);
    let mut current = offset;
    loop {
        let frame: FileReply = tokio::select! { _ = cancel.cancelled() => return Ok(()), f = read_frame(stream) => f? };
        match frame {
            FileReply::Chunk { offset, data } => {
                ensure!(
                    offset == current
                        && !data.is_empty()
                        && data.len() <= CHUNK_SIZE
                        && current + data.len() as u64 <= size,
                    "invalid upload chunk"
                );
                tokio::io::AsyncWriteExt::write_all(&mut file, &data).await?;
                file.sync_data().await?;
                current += data.len() as u64;
            }
            FileReply::Complete { sha256 } => {
                ensure!(sha256 == expected && current == size, "incomplete upload");
                break;
            }
            FileReply::Error(e) => bail!("client file operation failed: {e}"),
            _ => bail!("unexpected upload frame"),
        }
    }
    drop(file);
    let hash_file = root.open(&stage)?.into_std();
    let actual = blocking(move || file_info_handle(hash_file).map(|(_, h)| h)).await?;
    ensure!(
        actual == expected,
        "upload checksum mismatch; partial data retained for retry"
    );
    commit_stage(root, &stage, &checkpoint, &dest, overwrite)?;
    write_frame(
        stream,
        &FileReply::Complete {
            sha256: expected.into(),
        },
    )
    .await
}

fn dispatch(root: &Dir, req: FileRequest) -> Result<FileReply> {
    match req {
        FileRequest::List { path } => {
            let path = checked(root, &path, false)?;
            let mut entries = Vec::new();
            for entry in root.read_dir(path)? {
                let entry = entry?;
                let meta = entry.metadata()?;
                entries.push(FileEntry {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    is_dir: meta.is_dir(),
                    size: meta.len(),
                    modified: modified(&meta),
                });
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(FileReply::Entries(entries))
        }
        FileRequest::Mkdir { path } => {
            let p = checked(root, &path, true)?;
            ensure!(
                !p.as_os_str().is_empty(),
                "cannot create the root directory"
            );
            root.create_dir_all(p)?;
            Ok(FileReply::Ok)
        }
        FileRequest::Rename { from, to } => {
            let f = checked(root, &from, false)?;
            let t = checked(root, &to, true)?;
            root.rename(f, root, t)?;
            Ok(FileReply::Ok)
        }
        FileRequest::Copy { from, to } => {
            let f = checked(root, &from, false)?;
            let t = checked(root, &to, true)?;
            root.copy(f, root, t)?;
            Ok(FileReply::Ok)
        }
        FileRequest::Delete { path, recursive } => {
            let p = checked(root, &path, false)?;
            ensure!(
                !p.as_os_str().is_empty(),
                "cannot delete the root directory"
            );
            let m = root.symlink_metadata(&p)?;
            if m.is_dir() {
                if recursive {
                    root.remove_dir_all(p)?
                } else {
                    root.remove_dir(p)?
                }
            } else {
                root.remove_file(p)?
            };
            Ok(FileReply::Ok)
        }
        FileRequest::Stat { path } => {
            let p = checked(root, &path, false)?;
            let m = root.symlink_metadata(&p)?;
            Ok(FileReply::Metadata(FileEntry {
                name: p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                is_dir: m.is_dir(),
                size: m.len(),
                modified: modified(&m),
            }))
        }
        FileRequest::SetPermissions { path, mode } => {
            let p = checked(root, &path, false)?;
            set_mode(root, &p, mode)?;
            Ok(FileReply::Ok)
        }
        FileRequest::Upload { .. } | FileRequest::Download { .. } => {
            bail!("streaming request handled separately")
        }
    }
}

fn checked(root: &Dir, raw: &str, allow_missing_final: bool) -> Result<PathBuf> {
    let path = Path::new(raw);
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(p) => out.push(p),
            _ => bail!("path must be a relative, normalized path"),
        }
    }
    if raw.is_empty() {
        return Ok(out);
    }
    ensure!(!out.as_os_str().is_empty(), "invalid path");
    let components: Vec<_> = out.components().collect();
    for (i, _) in components.iter().enumerate() {
        let prefix = components[..=i].iter().collect::<PathBuf>();
        match root.symlink_metadata(&prefix) {
            Ok(meta) => {
                ensure!(
                    !meta.file_type().is_symlink(),
                    "symbolic links are not allowed in file paths"
                );
                if i + 1 < components.len() {
                    ensure!(meta.is_dir(), "path parent is not a directory");
                }
            }
            Err(e)
                if allow_missing_final
                    && i + 1 == components.len()
                    && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}
fn modified(m: &cap_std::fs::Metadata) -> Option<u64> {
    m.modified()
        .ok()
        .and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}
fn file_info(path: &Path) -> Result<(u64, String)> {
    let mut f = std::fs::File::open(path)?;
    hash_reader(&mut f)
}
fn file_info_handle(mut f: std::fs::File) -> Result<(u64, String)> {
    hash_reader(&mut f)
}
fn hash_reader<R: Read>(r: &mut R) -> Result<(u64, String)> {
    let mut h = Sha256::new();
    let mut n = 0;
    let mut b = [0; CHUNK_SIZE];
    loop {
        let c = r.read(&mut b)?;
        if c == 0 {
            break;
        }
        h.update(&b[..c]);
        n += c as u64;
    }
    Ok((n, hex::encode(h.finalize())))
}
fn is_hash(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())
}
fn staging_identity(peer: &str, dest: &Path, size: u64, hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(peer.as_bytes());
    h.update([0]);
    h.update(dest.as_os_str().to_string_lossy().as_bytes());
    h.update([0]);
    h.update(size.to_be_bytes());
    h.update(hash.as_bytes());
    hex::encode(h.finalize())
}
fn prepare_stage(
    root: &Dir,
    stage: &Path,
    checkpoint: &Path,
    identity: &str,
    size: u64,
) -> Result<u64> {
    match root.read_to_string(checkpoint) {
        Ok(v) if v == identity => {}
        Ok(_) => {
            let _ = root.remove_file(stage);
            write_checkpoint(root, checkpoint, identity)?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_checkpoint(root, checkpoint, identity)?
        }
        Err(e) => return Err(e.into()),
    };
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true);
    let f = root.open_with(stage, &o)?;
    let n = f.metadata()?.len();
    ensure!(n <= size, "stored partial exceeds requested upload size");
    f.sync_all()?;
    Ok(n)
}
fn write_checkpoint(root: &Dir, path: &Path, contents: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let mut file = root.open_with(path, &options)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}
fn commit_stage(
    root: &Dir,
    stage: &Path,
    checkpoint: &Path,
    dest: &Path,
    overwrite: bool,
) -> Result<()> {
    if overwrite {
        root.rename(stage, root, dest)?
    } else {
        root.hard_link(stage, root, dest)
            .context("destination already exists or cannot publish upload")?;
        root.remove_file(stage)?
    }
    let _ = root.remove_file(checkpoint);
    Ok(())
}
fn part_path(destination: &Path) -> Result<PathBuf> {
    let name = destination
        .file_name()
        .ok_or_else(|| anyhow!("destination must name a file"))?;
    Ok(destination.with_file_name(format!("{}.part", name.to_string_lossy())))
}
fn download_state_path(part: &Path) -> PathBuf {
    part.with_file_name(format!(
        "{}.state",
        part.file_name().unwrap_or_default().to_string_lossy()
    ))
}
fn download_state(remote: &str, size: u64, hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(remote.as_bytes());
    h.update([0]);
    h.update(size.to_be_bytes());
    h.update(hash.as_bytes());
    hex::encode(h.finalize())
}
async fn write_local_durable(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    let mut file = options.open(path).await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, contents).await?;
    file.sync_all().await?;
    Ok(())
}
fn publish_local(part: &Path, dest: &Path, overwrite: bool) -> Result<()> {
    validate_local_destination(dest, overwrite)?;
    if overwrite {
        std::fs::rename(part, dest)?
    } else {
        std::fs::hard_link(part, dest).context("destination already exists")?;
        std::fs::remove_file(part)?
    }
    Ok(())
}
fn reject_local_symlink(path: &Path) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        ensure!(
            !metadata.file_type().is_symlink(),
            "refusing symbolic link in local transfer state"
        );
    }
    Ok(())
}
fn validate_local_destination(destination: &Path, overwrite: bool) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination must have a parent directory"))?;
    let parent_meta = std::fs::symlink_metadata(parent).context("reading destination parent")?;
    ensure!(
        parent_meta.is_dir() && !parent_meta.file_type().is_symlink(),
        "destination parent must be a real directory"
    );
    if let Ok(meta) = std::fs::symlink_metadata(destination) {
        ensure!(
            !meta.file_type().is_symlink(),
            "destination cannot be a symbolic link"
        );
        ensure!(overwrite, "destination already exists");
    }
    Ok(())
}
fn reply_result(reply: FileReply) -> Result<FileReply> {
    if let FileReply::Error(e) = &reply {
        bail!("remote file operation failed: {e}")
    }
    Ok(reply)
}
fn set_mode(root: &Dir, path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = std::fs::Permissions::from_mode(mode);
        root.set_permissions(path, Permissions::from_std(p))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (root, path, mode);
        bail!("POSIX file modes are unsupported on this platform");
    }
    Ok(())
}
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .context("file worker panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_escape_and_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let d = Dir::open_ambient_dir(temp.path(), ambient_authority()).unwrap();
        assert!(checked(&d, "../x", false).is_err());
        assert!(checked(&d, "/tmp/x", false).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/tmp", temp.path().join("link")).unwrap();
            assert!(checked(&d, "link/x", false).is_err());
        }
    }

    #[tokio::test]
    async fn upload_resumes_and_preserves_existing_destination() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source.bin");
        let bytes = (0..(CHUNK_SIZE * 2 + 19))
            .map(|n| (n % 251) as u8)
            .collect::<Vec<_>>();
        std::fs::write(&source, &bytes)?;
        let (_, hash) = file_info(&source)?;
        let root = Dir::open_ambient_dir(temp.path(), ambient_authority())?;
        let dest = PathBuf::from("resume.bin");
        let id = staging_identity("test-peer", &dest, bytes.len() as u64, &hash);
        let stage = PathBuf::from(format!("{PART_PREFIX}{id}.part"));
        let checkpoint = PathBuf::from(format!("{PART_PREFIX}{id}.state"));
        root.write(&stage, &bytes[..CHUNK_SIZE])?;
        root.write(
            &checkpoint,
            format!(
                "peer=test-peer\npath={}\nsize={}\nsha256={hash}\n",
                dest.display(),
                bytes.len()
            ),
        )?;
        let (server, client) = tokio::io::duplex(CHUNK_SIZE * 4);
        let root_path = temp.path().to_owned();
        let task = tokio::spawn(serve(
            server,
            root_path,
            "test-peer".into(),
            CancellationToken::new(),
        ));
        push(client, &source, "resume.bin", false).await?;
        task.await??;
        assert_eq!(std::fs::read(temp.path().join("resume.bin"))?, bytes);
        let (server, client) = tokio::io::duplex(CHUNK_SIZE * 4);
        let root_path = temp.path().to_owned();
        let task = tokio::spawn(serve(
            server,
            root_path,
            "test-peer".into(),
            CancellationToken::new(),
        ));
        assert!(push(client, &source, "resume.bin", false).await.is_err());
        assert!(task.await?.is_err());
        assert_eq!(std::fs::read(temp.path().join("resume.bin"))?, bytes);
        Ok(())
    }
}
