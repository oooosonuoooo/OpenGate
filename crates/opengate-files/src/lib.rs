//! Capability-rooted file operations for authenticated OpenGate file streams.

use std::{
    io::{Read, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::UNIX_EPOCH,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use opengate_protocol::{CHUNK_SIZE, FileEntry, FileReply, FileRequest, read_frame, write_frame};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

const PART_PREFIX: &str = ".opengate-upload-";

/// A durable byte position reported after each accepted transfer chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferProgress {
    pub transferred: u64,
    pub total: u64,
}

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
    let result = match req {
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
                UploadSpec {
                    peer: &peer,
                    raw: &path,
                    size,
                    expected: &sha256,
                    overwrite,
                },
                cancel,
            )
            .await
        }
        other => match blocking(move || dispatch(&root, other)).await {
            Ok(reply) => write_frame(&mut stream, &reply).await,
            Err(error) => write_frame(&mut stream, &FileReply::Error(error.to_string())).await,
        },
    };
    // A request-level error is a permanent rejection for this stream (bad path,
    // checksum, offset, or overwrite policy).  Frame it so callers do not mistake
    // a cleanly rejected operation for a transport interruption worth retrying.
    if let Err(error) = result {
        write_frame(&mut stream, &FileReply::Error(error.to_string())).await
    } else {
        Ok(())
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
pub async fn push<S>(stream: S, source: &Path, remote: &str, overwrite: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    push_with_progress(
        stream,
        source,
        remote,
        overwrite,
        CancellationToken::new(),
        |_| {},
    )
    .await
}

/// Upload with cancellation and durable byte-level progress notifications.
pub async fn push_with_progress<S, F>(
    mut stream: S,
    source: &Path,
    remote: &str,
    overwrite: bool,
    cancel: CancellationToken,
    mut progress: F,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut(TransferProgress),
{
    let source = source.to_owned();
    let source_for_info = source.clone();
    let (size, hash) = blocking(move || file_info(&source_for_info)).await?;
    let request = FileRequest::Upload {
        path: remote.into(),
        size,
        sha256: hash.clone(),
        overwrite,
    };
    tokio::select! {
        _ = cancel.cancelled() => bail!("upload cancelled"),
        result = write_frame(&mut stream, &request) => result?,
    }
    let ready = tokio::select! {
        _ = cancel.cancelled() => bail!("upload cancelled"),
        result = read_frame(&mut stream) => reply_result(result?)?,
    };
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
    progress(TransferProgress {
        transferred: current,
        total: size,
    });
    let mut buf = vec![0_u8; CHUNK_SIZE];
    while current < size {
        let read = tokio::select! {
            _ = cancel.cancelled() => bail!("upload cancelled"),
            result = tokio::io::AsyncReadExt::read(&mut file, &mut buf) => result?,
        };
        ensure!(read != 0, "source changed during upload");
        let chunk = FileReply::Chunk {
            offset: current,
            data: buf[..read].to_vec(),
        };
        tokio::select! {
            _ = cancel.cancelled() => bail!("upload cancelled"),
            result = write_frame(&mut stream, &chunk) => result?,
        }
        current += read as u64;
        progress(TransferProgress {
            transferred: current,
            total: size,
        });
    }
    let complete = FileReply::Complete {
        sha256: hash.clone(),
    };
    tokio::select! {
        _ = cancel.cancelled() => bail!("upload cancelled"),
        result = write_frame(&mut stream, &complete) => result?,
    }
    let completion = tokio::select! {
        _ = cancel.cancelled() => bail!("upload cancelled"),
        result = read_frame(&mut stream) => reply_result(result?)?,
    };
    match completion {
        FileReply::Complete { sha256 } if sha256 == hash => Ok(()),
        _ => bail!("invalid upload completion reply"),
    }
}

/// Download one file into a durable sibling `.part` file, verify it, then atomically publish it.
pub async fn pull<S>(stream: S, remote: &str, destination: &Path, overwrite: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pull_with_progress(
        stream,
        remote,
        destination,
        overwrite,
        CancellationToken::new(),
        |_| {},
    )
    .await
}

/// Download with cancellation and durable byte-level progress notifications.
pub async fn pull_with_progress<S, F>(
    mut stream: S,
    remote: &str,
    destination: &Path,
    overwrite: bool,
    cancel: CancellationToken,
    mut progress: F,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut(TransferProgress),
{
    validate_local_destination(destination, overwrite)?;
    let part = part_path(destination)?;
    let state_path = download_state_path(&part);
    let prior_state = read_local_state(&state_path)?;
    let local_offset = local_part_len(&part)?;
    if local_offset != 0 && prior_state.is_none() {
        bail!("refusing an unowned partial download; remove it manually before retrying");
    }
    let request = FileRequest::Download {
        path: remote.into(),
        offset: local_offset,
    };
    tokio::select! {
        _ = cancel.cancelled() => bail!("download cancelled"),
        result = write_frame(&mut stream, &request) => result?,
    }
    let ready = tokio::select! {
        _ = cancel.cancelled() => bail!("download cancelled"),
        result = read_frame(&mut stream) => reply_result(result?)?,
    };
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
        ensure!(
            prior == state,
            "remote file identity changed; existing transfer state was preserved"
        );
    } else {
        ensure!(
            local_offset == 0,
            "refusing an unowned partial download; remove it manually before retrying"
        );
        write_local_state_new(&state_path, state.as_bytes())?;
    }
    let part_file = if local_offset == 0 {
        open_local_part_new(&part)?
    } else {
        open_local_part_existing(&part)?
    };
    let mut file = tokio::fs::File::from_std(part_file);
    tokio::io::AsyncSeekExt::seek(&mut file, SeekFrom::Start(offset)).await?;
    let mut current = offset;
    progress(TransferProgress {
        transferred: current,
        total: size,
    });
    loop {
        let frame: FileReply = tokio::select! {
            _ = cancel.cancelled() => bail!("download cancelled"),
            result = read_frame(&mut stream) => result?,
        };
        match frame {
            FileReply::Chunk { offset, data } => {
                ensure!(
                    offset == current
                        && data.len() <= CHUNK_SIZE
                        && current + data.len() as u64 <= size,
                    "invalid download chunk"
                );
                tokio::io::AsyncWriteExt::write_all(&mut file, &data).await?;
                // The offset we advertise on a later connection must survive a
                // process or host crash, not merely be present in the page cache.
                file.sync_data().await?;
                current += data.len() as u64;
                progress(TransferProgress {
                    transferred: current,
                    total: size,
                });
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
    // Never clean up a sidecar whose identity changed underneath us.  Leaving a
    // stale checkpoint is safer than unlinking a file we did not create.
    #[cfg(unix)]
    if read_local_state(&state_path)?.as_deref() == Some(state.as_str()) {
        let _ = std::fs::remove_file(state_path);
    }
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

struct UploadSpec<'a> {
    peer: &'a str,
    raw: &'a str,
    size: u64,
    expected: &'a str,
    overwrite: bool,
}

async fn upload<S>(
    stream: &mut S,
    root: &Dir,
    spec: UploadSpec<'_>,
    cancel: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let UploadSpec {
        peer,
        raw,
        size,
        expected,
        overwrite,
    } = spec;
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
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".opengate-")
                {
                    continue;
                }
                ensure!(
                    entries.len() < 4096,
                    "directory listing exceeds 4096 entries; select a subdirectory"
                );
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
            if !p.as_os_str().is_empty() {
                root.create_dir_all(p)?;
            }
            Ok(FileReply::Ok)
        }
        FileRequest::Rename { from, to } => {
            let f = checked(root, &from, false)?;
            let t = checked(root, &to, true)?;
            ensure!(
                f != Path::new(".") && t != Path::new("."),
                "cannot move or copy the file access root"
            );
            ensure!(!root.try_exists(&t)?, "rename destination already exists");
            root.rename(f, root, t)?;
            Ok(FileReply::Ok)
        }
        FileRequest::Copy { from, to } => {
            let f = checked(root, &from, false)?;
            let t = checked(root, &to, true)?;
            ensure!(
                f != Path::new(".") && t != Path::new("."),
                "cannot move or copy the file access root"
            );
            let mut source = root.open(f)?;
            let mut target = root.open_with(t, OpenOptions::new().write(true).create_new(true))?;
            std::io::copy(&mut source, &mut target)?;
            target.sync_all()?;
            Ok(FileReply::Ok)
        }
        FileRequest::Delete { path, recursive } => {
            let p = checked(root, &path, false)?;
            ensure!(
                !p.as_os_str().is_empty() && p != Path::new("."),
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
    if raw == "." || raw.is_empty() {
        return Ok(PathBuf::from("."));
    }
    let path = Path::new(raw);
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(p) => {
                ensure!(
                    !p.to_string_lossy().starts_with(".opengate-"),
                    "reserved OpenGate staging path"
                );
                out.push(p);
            }
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
fn publish_local(part: &Path, dest: &Path, overwrite: bool) -> Result<()> {
    validate_local_destination(dest, overwrite)?;
    reject_local_symlink(part)?;
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
/// The durable download state lives next to the requested destination.  On Unix
/// every open uses `O_NOFOLLOW`, so a swap to a symlink between validation and
/// opening is rejected by the kernel.  Windows has no equivalent portable std API;
/// create-new is safe there, while existing state is refused rather than followed.
fn read_local_state(path: &Path) -> Result<Option<String>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing symbolic link in local transfer state")
        }
        Ok(_) => {}
        Err(error) => return Err(error.into()),
    }
    match open_local_existing(path, false) {
        Ok(mut file) => {
            let mut value = String::new();
            file.read_to_string(&mut value)?;
            Ok(Some(value))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn local_part_len(path: &Path) -> Result<u64> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing symbolic link in local transfer state")
        }
        Ok(_) => {}
        Err(error) => return Err(error.into()),
    }
    match open_local_existing(path, true) {
        Ok(file) => Ok(file.metadata()?.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}
fn write_local_state_new(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = open_local_new(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}
fn open_local_part_new(path: &Path) -> Result<std::fs::File> {
    open_local_new(path).map_err(Into::into)
}
fn open_local_part_existing(path: &Path) -> Result<std::fs::File> {
    open_local_existing(path, true).map_err(Into::into)
}
fn open_local_new(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    no_follow(&mut options);
    let file = options.open(path)?;
    ensure_regular(&file)?;
    Ok(file)
}
fn open_local_existing(path: &Path, write: bool) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        let _ = (path, write);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "resuming local transfer state is unsupported on Windows until a no-reparse-point open is available",
        ));
    }
    #[cfg(not(windows))]
    {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(write);
        no_follow(&mut options);
        let file = options.open(path)?;
        ensure_regular(&file)?;
        Ok(file)
    }
}
#[cfg(unix)]
fn no_follow(options: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}
#[cfg(not(unix))]
fn no_follow(_options: &mut std::fs::OpenOptions) {}
fn ensure_regular(file: &std::fs::File) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "local transfer state must be a regular file",
        ));
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
        root.set_permissions(path, cap_std::fs::Permissions::from_std(p))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (root, path, mode);
        bail!("POSIX file modes are unsupported on this platform")
    }
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
        task.await??;
        assert_eq!(std::fs::read(temp.path().join("resume.bin"))?, bytes);
        Ok(())
    }

    #[tokio::test]
    async fn interrupted_upload_resumes_at_the_durable_server_offset() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let bytes = (0..(CHUNK_SIZE + 37))
            .map(|n| (n % 251) as u8)
            .collect::<Vec<_>>();
        let source = temp.path().join("source.bin");
        std::fs::write(&source, &bytes)?;
        let (_, hash) = file_info(&source)?;

        let (server, mut client) = tokio::io::duplex(CHUNK_SIZE * 2);
        let first = tokio::spawn(serve(
            server,
            temp.path().to_owned(),
            "peer".into(),
            CancellationToken::new(),
        ));
        write_frame(
            &mut client,
            &FileRequest::Upload {
                path: "resume.bin".into(),
                size: bytes.len() as u64,
                sha256: hash.clone(),
                overwrite: false,
            },
        )
        .await?;
        assert!(matches!(
            read_frame(&mut client).await?,
            FileReply::Ready { offset: 0, .. }
        ));
        write_frame(
            &mut client,
            &FileReply::Chunk {
                offset: 0,
                data: bytes[..CHUNK_SIZE].to_vec(),
            },
        )
        .await?;
        drop(client);
        assert!(first.await?.is_err());

        let (server, mut client) = tokio::io::duplex(CHUNK_SIZE * 2);
        let second = tokio::spawn(serve(
            server,
            temp.path().to_owned(),
            "peer".into(),
            CancellationToken::new(),
        ));
        write_frame(
            &mut client,
            &FileRequest::Upload {
                path: "resume.bin".into(),
                size: bytes.len() as u64,
                sha256: hash.clone(),
                overwrite: false,
            },
        )
        .await?;
        assert!(matches!(
            read_frame(&mut client).await?,
            FileReply::Ready { offset, .. } if offset == CHUNK_SIZE as u64
        ));
        write_frame(
            &mut client,
            &FileReply::Chunk {
                offset: CHUNK_SIZE as u64,
                data: bytes[CHUNK_SIZE..].to_vec(),
            },
        )
        .await?;
        write_frame(
            &mut client,
            &FileReply::Complete {
                sha256: hash.clone(),
            },
        )
        .await?;
        assert!(matches!(
            read_frame(&mut client).await?,
            FileReply::Complete { sha256 } if sha256 == hash
        ));
        second.await??;
        assert_eq!(std::fs::read(temp.path().join("resume.bin"))?, bytes);
        Ok(())
    }

    #[tokio::test]
    async fn interrupted_download_resumes_at_the_durable_client_offset() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let bytes = (0..(CHUNK_SIZE + 29))
            .map(|n| (n % 239) as u8)
            .collect::<Vec<_>>();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = hex::encode(hasher.finalize());
        let destination = temp.path().join("received.bin");

        let (mut server, client) = tokio::io::duplex(CHUNK_SIZE * 2);
        let first = tokio::spawn({
            let hash = hash.clone();
            let first_chunk = bytes[..CHUNK_SIZE].to_vec();
            async move {
                assert!(matches!(
                    read_frame(&mut server).await?,
                    FileRequest::Download { offset: 0, .. }
                ));
                write_frame(
                    &mut server,
                    &FileReply::Ready {
                        offset: 0,
                        size: (CHUNK_SIZE + 29) as u64,
                        sha256: hash,
                    },
                )
                .await?;
                write_frame(
                    &mut server,
                    &FileReply::Chunk {
                        offset: 0,
                        data: first_chunk,
                    },
                )
                .await?;
                Ok::<(), anyhow::Error>(())
            }
        });
        assert!(
            pull(client, "remote.bin", &destination, false)
                .await
                .is_err()
        );
        first.await??;

        let (mut server, client) = tokio::io::duplex(CHUNK_SIZE * 2);
        let second = tokio::spawn({
            let hash = hash.clone();
            let remainder = bytes[CHUNK_SIZE..].to_vec();
            async move {
                assert!(matches!(
                    read_frame(&mut server).await?,
                    FileRequest::Download { offset, .. } if offset == CHUNK_SIZE as u64
                ));
                write_frame(
                    &mut server,
                    &FileReply::Ready {
                        offset: CHUNK_SIZE as u64,
                        size: (CHUNK_SIZE + 29) as u64,
                        sha256: hash.clone(),
                    },
                )
                .await?;
                write_frame(
                    &mut server,
                    &FileReply::Chunk {
                        offset: CHUNK_SIZE as u64,
                        data: remainder,
                    },
                )
                .await?;
                write_frame(&mut server, &FileReply::Complete { sha256: hash }).await?;
                Ok::<(), anyhow::Error>(())
            }
        });
        let mut progress = Vec::new();
        pull_with_progress(
            client,
            "remote.bin",
            &destination,
            false,
            CancellationToken::new(),
            |position| progress.push(position),
        )
        .await?;
        second.await??;
        assert_eq!(std::fs::read(destination)?, bytes);
        assert_eq!(
            progress,
            vec![
                TransferProgress {
                    transferred: CHUNK_SIZE as u64,
                    total: (CHUNK_SIZE + 29) as u64,
                },
                TransferProgress {
                    transferred: (CHUNK_SIZE + 29) as u64,
                    total: (CHUNK_SIZE + 29) as u64,
                },
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_pull_creates_no_local_transfer_state() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("cancelled.bin");
        let part = part_path(&destination)?;
        let state = download_state_path(&part);
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let (_, client) = tokio::io::duplex(1024);
        assert!(
            pull_with_progress(
                client,
                "remote.bin",
                &destination,
                false,
                cancellation,
                |_| {},
            )
            .await
            .is_err()
        );
        assert!(!part.exists());
        assert!(!state.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pull_refuses_sidecar_symlinks_without_touching_their_targets() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("received.bin");
        let part = part_path(&destination)?;
        let state = download_state_path(&part);
        let protected = temp.path().join("protected.txt");
        std::fs::write(&protected, "keep")?;
        std::os::unix::fs::symlink(&protected, &part)?;
        let (_, client) = tokio::io::duplex(1024);
        assert!(
            pull(client, "remote.bin", &destination, false)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&protected)?, "keep");
        std::fs::remove_file(&part)?;
        std::os::unix::fs::symlink(&protected, &state)?;
        let (_, client) = tokio::io::duplex(1024);
        assert!(
            pull(client, "remote.bin", &destination, false)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&protected)?, "keep");
        Ok(())
    }

    #[test]
    fn directory_operations_stay_inside_the_capability_root() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = Dir::open_ambient_dir(temp.path(), ambient_authority())?;
        assert!(matches!(
            dispatch(
                &root,
                FileRequest::Mkdir {
                    path: "nested".into()
                }
            )?,
            FileReply::Ok
        ));
        root.write("nested/source.txt", b"payload")?;
        assert!(matches!(
            dispatch(
                &root,
                FileRequest::Copy {
                    from: "nested/source.txt".into(),
                    to: "nested/copy.txt".into(),
                },
            )?,
            FileReply::Ok
        ));
        assert!(matches!(
            dispatch(
                &root,
                FileRequest::Rename {
                    from: "nested/copy.txt".into(),
                    to: "nested/renamed.txt".into(),
                },
            )?,
            FileReply::Ok
        ));
        assert!(matches!(
            dispatch(
                &root,
                FileRequest::Stat {
                    path: "nested/renamed.txt".into()
                }
            )?,
            FileReply::Metadata(FileEntry {
                size: 7,
                is_dir: false,
                ..
            })
        ));
        assert!(matches!(
            dispatch(
                &root,
                FileRequest::Delete {
                    path: "nested".into(),
                    recursive: true,
                },
            )?,
            FileReply::Ok
        ));
        assert!(!temp.path().join("nested").exists());
        Ok(())
    }
    #[test]
    fn file_root_and_internal_staging_visibility() -> Result<()> {
        let temp = tempfile::tempdir()?;
        std::fs::write(temp.path().join(".opengate-upload-private"), b"private")?;
        std::fs::write(temp.path().join("visible.txt"), b"visible")?;
        let root = Dir::open_ambient_dir(temp.path(), ambient_authority())?;
        let reply = dispatch(&root, FileRequest::List { path: ".".into() })?;
        let FileReply::Entries(entries) = reply else {
            bail!("expected entries")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "visible.txt");
        assert!(checked(&root, ".opengate-upload-private", false).is_err());
        Ok(())
    }
}
