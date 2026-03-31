# nginx-qlog-adapter

Converts nginx QUIC debug logs into [qlog](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/) `.sqlog` files for analysis in tools like [qvis](https://qvis.quictools.info/).

One `.sqlog` file is produced per QUIC connection, named after its source connection ID.

> **qlog drafts:** output targets [draft-ietf-quic-qlog-main-schema-05](https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-05) and [draft-ietf-quic-qlog-quic-events-03](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/03/). These are older drafts, but [qvis](https://qvis.quictools.info/) unfortunately only supports these versions.

## Requirements

nginx built with `--with-debug` and QUIC support, logging at debug level.

## Build

```sh
cargo build --release
```

## Usage

```sh
nginx-qlog-adapter <error.log> [-o <output_dir>]
```

`-o` defaults to the current directory.

## nginx configuration

```nginx
error_log /var/log/nginx/error.log debug;
```
