# Benchmark logs

Three nginx QUIC debug logs of increasing scale.

## Files

| File | Size | Lines | Description |
|------|------|-------|-------------|
| `s.log` | 14 MB | 164 K | 100 requests, 100 KB files |
| `m.log` | 606 MB | 6.57 M | 1 000 requests, 1 MB files |
| `l.log` | 2.9 GB | 31.3 M | 5 000 requests, 1 MB files |

## How they were generated

Each workload used 10 parallel QUIC connections (`-c 10`) via `h2load` against
a VM running nginx 1.29.6 with HTTP/3 enabled.

```sh
h2load --alpn-list=h3 -c 10 -n 100  "https://<host>/100kb.bin"  # s.log
h2load --alpn-list=h3 -c 10 -n 1000 "https://<host>/1mb.bin"    # m.log
h2load --alpn-list=h3 -c 10 -n 5000 "https://<host>/1mb.bin"    # l.log
```

## Benchmark results

Measured on Apple M4 Pro, macOS 26.3.1, Rust 1.93.1 (`cargo build --release`).
Wall-clock time via `hyperfine` (1 warm-up run); peak RSS via `/usr/bin/time -l`.

| Workload | Wall time (mean ± σ) | Throughput | Peak RSS |
|----------|----------------------|------------|----------|
| S | 49 ms ± 1 ms | 286 MB/s | 40 MB |
| M | 3.8 s ± 0.1 s | 159 MB/s | 1.28 GB |
| L | 51.3 s ± 0.7 s | 57 MB/s | 2.11 GB |
