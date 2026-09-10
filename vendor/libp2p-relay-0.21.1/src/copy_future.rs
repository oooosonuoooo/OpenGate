// Copyright 2020 Parity Technologies (UK) Ltd.
// Copyright 2021 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Helper to interconnect two substreams, connecting the receiver side of A with the sender side of
//! B and vice versa.
//!
//! Inspired by [`futures::io::Copy`].

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use futures::{
    future::{Future, FutureExt},
    io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader},
    ready,
};
use futures_timer::Delay;
use web_time::Instant;

/// The maximum amount copied by one paced write. Together with `BufReader`, this keeps the
/// relay's per-circuit buffering fixed regardless of peer-provided frame sizes.
const MAX_PACED_WRITE: usize = 16 * 1024;

/// A deterministic leaky-bucket schedule. It deliberately schedules opaque bytes rather than
/// storing them: a caller waits until its reservation is due before writing to a peer stream.
#[derive(Debug)]
pub(crate) struct BandwidthLimiter {
    bytes_per_second: u64,
    next_available: Instant,
}

impl BandwidthLimiter {
    pub(crate) fn new(bytes_per_second: u64) -> Self {
        debug_assert!(bytes_per_second > 0);
        Self {
            bytes_per_second,
            next_available: Instant::now(),
        }
    }

    fn reserve_at(&mut self, bytes: usize, earliest: Instant) -> Instant {
        self.next_available = self.ready_at(bytes, earliest);
        self.next_available
    }

    fn ready_at(&self, bytes: usize, earliest: Instant) -> Instant {
        self.next_available.max(earliest) + duration_for(bytes, self.bytes_per_second)
    }
}

/// Paces one circuit and, when configured, a relay-wide limiter. A permit remains attached to a
/// pending write, so a backpressured destination cannot consume additional relay bandwidth.
struct Pacer {
    circuit: BandwidthLimiter,
    aggregate: Option<Arc<Mutex<BandwidthLimiter>>>,
    delay: Option<Delay>,
    permit: Option<usize>,
}

impl Pacer {
    fn new(
        bytes_per_second: u64,
        aggregate: Option<Arc<Mutex<BandwidthLimiter>>>,
    ) -> Option<Self> {
        (bytes_per_second > 0).then(|| Self {
            circuit: BandwidthLimiter::new(bytes_per_second),
            aggregate,
            delay: None,
            permit: None,
        })
    }

    fn poll_ready(&mut self, bytes: usize, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(permit) = self.permit {
            debug_assert_eq!(permit, bytes);
            return Poll::Ready(());
        }

        if let Some(delay) = self.delay.as_mut() {
            match delay.poll_unpin(cx) {
                Poll::Ready(()) => {
                    self.delay = None;
                    self.permit = Some(bytes);
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let now = Instant::now();
        let at = self.reserve(bytes, now);

        if at <= now {
            self.permit = Some(bytes);
            return Poll::Ready(());
        }

        self.delay = Some(Delay::new(at.duration_since(now)));
        self.poll_ready(bytes, cx)
    }

    fn reserve(&mut self, bytes: usize, now: Instant) -> Instant {
        if let Some(aggregate) = &self.aggregate {
            let mut aggregate = aggregate.lock().expect("relay bandwidth limiter lock poisoned");
            let ready = self
                .circuit
                .ready_at(bytes, now)
                .max(aggregate.ready_at(bytes, now));
            // Both buckets advance to the actual write time. This is intentionally conservative
            // when their rates differ: a delayed per-circuit write cannot later burst through the
            // relay-wide budget that had been reserved at an earlier time.
            self.circuit.next_available = ready;
            aggregate.next_available = ready;
            ready
        } else {
            self.circuit.reserve_at(bytes, now)
        }
    }

    fn finish_write(&mut self) {
        self.permit = None;
    }
}

fn duration_for(bytes: usize, bytes_per_second: u64) -> Duration {
    let bytes = bytes as u128;
    let rate = bytes_per_second as u128;
    let seconds = bytes / rate;
    let remainder = bytes % rate;
    let nanos = (remainder * 1_000_000_000).div_ceil(rate);
    Duration::from_secs(seconds as u64) + Duration::from_nanos(nanos as u64)
}

pub(crate) struct CopyFuture<S, D> {
    src: BufReader<S>,
    dst: BufReader<D>,

    max_circuit_duration: Delay,
    max_circuit_bytes: u64,
    bytes_sent: u64,
    pacer: Option<Pacer>,
}

impl<S: AsyncRead, D: AsyncRead> CopyFuture<S, D> {
    pub(crate) fn new(
        src: S,
        dst: D,
        max_circuit_duration: Duration,
        max_circuit_bytes: u64,
        max_circuit_bytes_per_second: u64,
        bandwidth_limiter: Option<Arc<Mutex<BandwidthLimiter>>>,
    ) -> Self {
        CopyFuture {
            src: BufReader::new(src),
            dst: BufReader::new(dst),
            max_circuit_duration: Delay::new(max_circuit_duration),
            max_circuit_bytes,
            bytes_sent: Default::default(),
            pacer: Pacer::new(max_circuit_bytes_per_second, bandwidth_limiter),
        }
    }
}

impl<S, D> Future for CopyFuture<S, D>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        loop {
            if this.max_circuit_bytes > 0 && this.bytes_sent > this.max_circuit_bytes {
                return Poll::Ready(Err(io::Error::other("Max circuit bytes reached.")));
            }

            enum Status {
                Pending,
                Done,
                Progressed,
            }

            let src_status = match forward_data(
                &mut this.src,
                &mut this.dst,
                this.pacer.as_mut(),
                cx,
            ) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => Status::Done,
                Poll::Ready(Ok(i)) => {
                    this.bytes_sent += i;
                    Status::Progressed
                }
                Poll::Pending => Status::Pending,
            };

            let dst_status = match forward_data(
                &mut this.dst,
                &mut this.src,
                this.pacer.as_mut(),
                cx,
            ) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => Status::Done,
                Poll::Ready(Ok(i)) => {
                    this.bytes_sent += i;
                    Status::Progressed
                }
                Poll::Pending => Status::Pending,
            };

            match (src_status, dst_status) {
                // Both source and destination are done sending data.
                (Status::Done, Status::Done) => return Poll::Ready(Ok(())),
                // Either source or destination made progress.
                (Status::Progressed, _) | (_, Status::Progressed) => {}
                // Both are pending. Check if max circuit duration timer fired, otherwise return
                // Poll::Pending.
                (Status::Pending, Status::Pending) => break,
                // One is done sending data, the other is pending. Check if timer fired, otherwise
                // return Poll::Pending.
                (Status::Pending, Status::Done) | (Status::Done, Status::Pending) => break,
            }
        }

        if let Poll::Ready(()) = this.max_circuit_duration.poll_unpin(cx) {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }

        Poll::Pending
    }
}

/// Forwards data from `source` to `destination`.
///
/// Returns `0` when done, i.e. `source` having reached EOF, returns number of bytes sent otherwise,
/// thus indicating progress.
fn forward_data<S: AsyncBufRead + Unpin, D: AsyncWrite + Unpin>(
    mut src: &mut S,
    mut dst: &mut D,
    mut pacer: Option<&mut Pacer>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<u64>> {
    let buffer = match Pin::new(&mut src).poll_fill_buf(cx)? {
        Poll::Ready(buffer) => buffer,
        Poll::Pending => {
            let _ = Pin::new(&mut dst).poll_flush(cx)?;
            return Poll::Pending;
        }
    };

    if buffer.is_empty() {
        ready!(Pin::new(&mut dst).poll_flush(cx))?;
        ready!(Pin::new(&mut dst).poll_close(cx))?;
        return Poll::Ready(Ok(0));
    }

    let paced_len = buffer.len().min(MAX_PACED_WRITE);
    if let Some(pacer) = pacer.as_mut() {
        ready!(pacer.poll_ready(paced_len, cx));
    }
    let i = ready!(Pin::new(dst).poll_write(cx, &buffer[..paced_len]))?;
    if i == 0 {
        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
    }
    Pin::new(src).consume(i);
    if let Some(pacer) = pacer {
        pacer.finish_write();
    }

    Poll::Ready(Ok(i.try_into().expect("usize to fit into u64.")))
}

#[cfg(test)]
mod tests {
    use std::{
        io::ErrorKind,
        sync::{Arc, Mutex},
    };

    use futures::{executor::block_on, io::BufWriter};
    use quickcheck::QuickCheck;

    use super::*;

    #[test]
    fn quickcheck() {
        struct Connection {
            read: Vec<u8>,
            write: Vec<u8>,
        }

        impl AsyncWrite for Connection {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Pin::new(&mut self.write).poll_write(cx, buf)
            }

            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.write).poll_flush(cx)
            }

            fn poll_close(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.write).poll_close(cx)
            }
        }

        impl AsyncRead for Connection {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<std::io::Result<usize>> {
                let n = std::cmp::min(self.read.len(), buf.len());
                buf[0..n].copy_from_slice(&self.read[0..n]);
                self.read = self.read.split_off(n);
                Poll::Ready(Ok(n))
            }
        }

        fn prop(a: Vec<u8>, b: Vec<u8>, max_circuit_bytes: u64) {
            let connection_a = Connection {
                read: a.clone(),
                write: Vec::new(),
            };

            let connection_b = Connection {
                read: b.clone(),
                write: Vec::new(),
            };

            let mut copy_future = CopyFuture::new(
                connection_a,
                connection_b,
                Duration::from_secs(60),
                max_circuit_bytes,
                0,
                None,
            );

            match block_on(&mut copy_future) {
                Ok(()) => {
                    assert_eq!(copy_future.src.into_inner().write, b);
                    assert_eq!(copy_future.dst.into_inner().write, a);
                }
                Err(error) => {
                    assert_eq!(error.kind(), ErrorKind::Other);
                    assert_eq!(error.to_string(), "Max circuit bytes reached.");
                    assert!(a.len() + b.len() > max_circuit_bytes as usize);
                }
            }
        }

        QuickCheck::new().quickcheck(prop as fn(_, _, _))
    }

    #[test]
    fn max_circuit_duration() {
        struct PendingConnection {}

        impl AsyncWrite for PendingConnection {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Poll::Pending
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }

            fn poll_close(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }
        }

        impl AsyncRead for PendingConnection {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut [u8],
            ) -> Poll<std::io::Result<usize>> {
                Poll::Pending
            }
        }

        let copy_future = CopyFuture::new(
            PendingConnection {},
            PendingConnection {},
            Duration::from_millis(1),
            u64::MAX,
            0,
            None,
        );

        std::thread::sleep(Duration::from_millis(2));

        let error =
            block_on(copy_future).expect_err("Expect maximum circuit duration to be reached.");
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn per_circuit_scheduler_limits_both_directions_together() {
        let aggregate = Arc::new(Mutex::new(BandwidthLimiter::new(1_000_000)));
        let mut circuit = Pacer::new(1_000, Some(aggregate)).expect("nonzero circuit rate");
        let now = Instant::now();

        let first = circuit.reserve(1_000, now);
        let second = circuit.reserve(1_000, now);

        assert!(first.duration_since(now) >= Duration::from_secs(1));
        assert!(
            second.duration_since(first) >= Duration::from_secs(1),
            "one circuit's two directions share its configured byte rate"
        );
    }

    #[test]
    fn aggregate_scheduler_serializes_multiple_circuits() {
        let aggregate = Arc::new(Mutex::new(BandwidthLimiter::new(1_000)));
        let mut first_circuit =
            Pacer::new(1_000_000, Some(aggregate.clone())).expect("nonzero circuit rate");
        let mut second_circuit =
            Pacer::new(1_000_000, Some(aggregate)).expect("nonzero circuit rate");
        let now = Instant::now();

        let first = first_circuit.reserve(1_000, now);
        let second = second_circuit.reserve(1_000, now);

        assert!(first.duration_since(now) >= Duration::from_secs(1));
        assert!(
            second.duration_since(first) >= Duration::from_secs(1),
            "the relay-wide limiter schedules bytes from separate circuits in one budget"
        );
    }

    #[test]
    fn paced_write_waits_without_buffering_when_aggregate_is_busy() {
        struct Source(Vec<u8>);

        impl AsyncRead for Source {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buffer: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                let n = self.0.len().min(buffer.len());
                buffer[..n].copy_from_slice(&self.0[..n]);
                self.0.drain(..n);
                Poll::Ready(Ok(n))
            }
        }

        struct Destination(usize);

        impl AsyncWrite for Destination {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buffer: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.0 += buffer.len();
                Poll::Ready(Ok(buffer.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let now = Instant::now();
        let aggregate = Arc::new(Mutex::new(BandwidthLimiter::new(10)));
        aggregate.lock().unwrap().reserve_at(10, now);
        let mut pacer = Pacer::new(10, Some(aggregate)).expect("nonzero circuit rate");
        let mut source = BufReader::new(Source(vec![7; MAX_PACED_WRITE]));
        let mut destination = Destination(0);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        assert!(matches!(
            forward_data(&mut source, &mut destination, Some(&mut pacer), &mut cx),
            Poll::Pending
        ));
        assert_eq!(destination.0, 0, "backpressure delays the write instead of buffering it");
        assert!(source.buffer().len() <= MAX_PACED_WRITE);
    }

    #[test]
    fn forward_data_should_flush_on_pending_source() {
        struct NeverEndingSource {
            read: Vec<u8>,
        }

        impl AsyncRead for NeverEndingSource {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<std::io::Result<usize>> {
                if let Some(b) = self.read.pop() {
                    buf[0] = b;
                    return Poll::Ready(Ok(1));
                }

                Poll::Pending
            }
        }

        struct RecordingDestination {
            method_calls: Vec<Method>,
        }

        #[derive(Debug, PartialEq)]
        enum Method {
            Write(Vec<u8>),
            Flush,
            Close,
        }

        impl AsyncWrite for RecordingDestination {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                self.method_calls.push(Method::Write(buf.to_vec()));
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.method_calls.push(Method::Flush);
                Poll::Ready(Ok(()))
            }

            fn poll_close(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.method_calls.push(Method::Close);
                Poll::Ready(Ok(()))
            }
        }

        // The source has two reads available, handing them out
        // on `AsyncRead::poll_read` one by one.
        let mut source = BufReader::new(NeverEndingSource { read: vec![1, 2] });

        // The destination is wrapped by a `BufWriter` with a capacity of `3`, i.e. one larger than
        // the available reads of the source. Without an explicit `AsyncWrite::poll_flush` the two
        // reads would thus never make it to the destination,
        // but instead be stuck in the buffer of the `BufWrite`.
        let mut destination = BufWriter::with_capacity(
            3,
            RecordingDestination {
                method_calls: vec![],
            },
        );

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        assert!(
            matches!(
                forward_data(&mut source, &mut destination, None, &mut cx),
                Poll::Ready(Ok(1)),
            ),
            "Expect `forward_data` to forward one read from the source to the wrapped destination."
        );
        assert_eq!(
            destination.get_ref().method_calls.as_slice(), &[],
            "Given that destination is wrapped with a `BufWrite`, the write doesn't (yet) make it to \
            the destination. The source might have more data available, thus `forward_data` has not \
            yet flushed.",
        );

        assert!(
            matches!(
                forward_data(&mut source, &mut destination, None, &mut cx),
                Poll::Ready(Ok(1)),
            ),
            "Expect `forward_data` to forward one read from the source to the wrapped destination."
        );
        assert_eq!(
            destination.get_ref().method_calls.as_slice(), &[],
            "Given that destination is wrapped with a `BufWrite`, the write doesn't (yet) make it to \
            the destination. The source might have more data available, thus `forward_data` has not \
            yet flushed.",
        );

        assert!(
            matches!(
                forward_data(&mut source, &mut destination, None, &mut cx),
                Poll::Pending,
            ),
            "The source has no more reads available, but does not close i.e. does not return \
            `Poll::Ready(Ok(1))` but instead `Poll::Pending`. Thus `forward_data` returns \
            `Poll::Pending` as well."
        );
        assert_eq!(
            destination.get_ref().method_calls.as_slice(),
            &[Method::Write(vec![2, 1]), Method::Flush],
            "Given that source had no more reads, `forward_data` calls flush, thus instructing the \
            `BufWriter` to flush the two buffered writes down to the destination."
        );
    }
}
