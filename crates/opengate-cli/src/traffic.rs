//! Measured application-stream counters and optional per-direction rate pacing.
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
#[derive(Default)]
pub struct Counters {
    pub received: AtomicU64,
    pub sent: AtomicU64,
    pub active: AtomicUsize,
}
struct Pacer {
    rate: u64,
    next: Instant,
    timer: Option<Pin<Box<Sleep>>>,
}
impl Pacer {
    fn new(rate: u64) -> Self {
        Self {
            rate,
            next: Instant::now(),
            timer: None,
        }
    }
    fn ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.rate == 0 {
            return Poll::Ready(());
        }
        if self.next <= Instant::now() {
            self.timer = None;
            return Poll::Ready(());
        }
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(self.next)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.timer = None;
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn charge(&mut self, bytes: usize) {
        if self.rate != 0 {
            self.next = Instant::now() + Duration::from_secs_f64(bytes as f64 / self.rate as f64);
        }
    }
}
/// At most 16 KiB is admitted in one paced I/O operation. The configured rate is
/// per stream and per direction; it is not falsely presented as an aggregate relay quota.
pub struct Metered<S> {
    inner: S,
    counters: Arc<Counters>,
    read: Pacer,
    write: Pacer,
}
impl<S> Metered<S> {
    pub fn new(inner: S, counters: Arc<Counters>, rate: u64) -> Self {
        counters.active.fetch_add(1, Ordering::Relaxed);
        Self {
            inner,
            counters,
            read: Pacer::new(rate),
            write: Pacer::new(rate),
        }
    }
}
impl<S> Drop for Metered<S> {
    fn drop(&mut self) {
        self.counters.active.fetch_sub(1, Ordering::Relaxed);
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read.ready(cx).is_pending() {
            return Poll::Pending;
        }
        let capacity = if this.read.rate == 0 {
            buf.remaining()
        } else {
            buf.remaining().min(16 * 1024)
        };
        let mut part = ReadBuf::new(buf.initialize_unfilled_to(capacity));
        match Pin::new(&mut this.inner).poll_read(cx, &mut part) {
            Poll::Ready(Ok(())) => {
                let count = part.filled().len();
                buf.advance(count);
                this.counters
                    .received
                    .fetch_add(count as u64, Ordering::Relaxed);
                this.read.charge(count);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write.ready(cx).is_pending() {
            return Poll::Pending;
        }
        let bytes = if this.write.rate == 0 {
            bytes
        } else {
            &bytes[..bytes.len().min(16 * 1024)]
        };
        match Pin::new(&mut this.inner).poll_write(cx, bytes) {
            Poll::Ready(Ok(count)) => {
                this.counters
                    .sent
                    .fetch_add(count as u64, Ordering::Relaxed);
                this.write.charge(count);
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn traffic_is_measured_and_paced_without_losing_bytes() -> anyhow::Result<()> {
        let (a, mut b) = tokio::io::duplex(1024);
        let counters = Arc::new(Counters::default());
        let mut a = Metered::new(a, counters.clone(), 1024 * 1024);
        let expected = vec![42u8; 128 * 1024];
        let sent = expected.clone();
        let started = Instant::now();
        let writer = tokio::spawn(async move {
            a.write_all(&sent).await?;
            a.shutdown().await?;
            io::Result::Ok(())
        });
        let mut received = Vec::new();
        b.read_to_end(&mut received).await?;
        writer.await??;
        assert_eq!(received, expected);
        assert_eq!(counters.sent.load(Ordering::Relaxed), 128 * 1024);
        assert_eq!(counters.active.load(Ordering::Relaxed), 0);
        assert!(started.elapsed() >= Duration::from_millis(80));
        Ok(())
    }
}
