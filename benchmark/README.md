# Benchmark logs

Three nginx QUIC debug logs of increasing scale.

## Files

| File | Size | Lines | Description |
|------|------|-------|-------------|
| `s.log` | 14 MB | 164 K | 100 requests, 100 KB files |
| `m.log` | 606 MB | 6.57 M | 1 000 requests, 1 MB files |
| `l.log` | 2.9 GB | 31.3 M | 5 000 requests, 1 MB files |

## How they were generated

Each workload used the same short-session HTTP/3 traffic pattern and downloaded files of fixed size via `h2load` against a VM running nginx 1.29.6 with HTTP/3 enabled.

```sh
h2load --alpn-list=h3 -n 100 -c 50 -m 1 -r 20 --rate-period=1s -T 2s  "https://<host>/100kb.bin" # s.log
h2load --alpn-list=h3 -n 1000 -c 50 -m 1 -r 20 --rate-period=1s -T 2s "https://<host>/1mb.bin" # m.log
h2load --alpn-list=h3 -n 5000 -c 50 -m 1 -r 20 --rate-period=1s -T 2s "https://<host>/1mb.bin" # l.log
```

## Benchmark results

Measured on Apple M4 Pro, macOS 26.3.1, Rust 1.93.1 (`cargo build --release`).
Wall-clock time via `hyperfine` (1 warm-up run); peak RSS via `/usr/bin/time -l`.

| Workload | Wall time (mean ± σ) | Throughput | Peak RSS |
|----------|----------------------|------------|----------|
| S | 65.8 ms ± 1.5 ms | 245 MB/s | 24 MB |
| M | 2.335 s ± 0.020 s | 268 MB/s | 714 GB |
| L | 11.149 s ± 0.078 s | 268 MB/s | 3.81 GB |
