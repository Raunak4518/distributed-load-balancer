# Edge Hardening

The load balancer implements multiple layers of defense to protect both itself and the backends from abuse and resource exhaustion.

## Connection Limits

The system applies two connection caps before a request is ever processed.

### Global Cap (`max_connections`)
The global cap uses a tokio semaphore. The accept loop acquires a permit *before* calling `accept()`. 

When the server reaches capacity, it stops accepting new connections. The kernel backlog absorbs incoming connections until it fills, at which point the kernel refuses the TCP handshake. This prevents the process from exhausting file descriptors on connections it would immediately discard.

### Per-IP Cap (`max_connections_per_ip`)
After a connection is accepted, the server checks the per-IP slot limit. If the source IP has reached its cap, the socket is dropped immediately. The per-IP map removes entries when the connection count drops to zero, preventing a client from growing the map by cycling source addresses.

## HTTP Defenses

### Header Read Timeout (`header_read_timeout_ms`)
HTTP/1.1 connections must complete sending headers within this timeout. This defends against slowloris attacks, where a client sends headers one byte at a time to tie up a connection slot.

### Body Size Limit (`max_request_body_bytes`)
The proxy bounds the request body size. If the client sends more than this limit, the proxy returns 413 Payload Too Large. This stops clients from overflowing memory before the request is forwarded.

### Body Read Timeout (`body_read_timeout_ms`)
A size limit alone does not bound time; a client could send 10 MiB at one byte per second. The body read timeout caps the total time a client has to transmit the body. Exceeding it returns 408 Request Timeout.

## HTTP/2 Defenses

### Rapid Reset (CVE-2023-44487)
In a Rapid Reset attack, a client opens an HTTP/2 stream and immediately sends an `RST_STREAM` frame to cancel it. This bypasses `max_concurrent_streams` because the streams are not concurrent. It forces the server to allocate and tear down state rapidly.

The `max_pending_accept_reset_streams` setting bounds the number of reset streams the server will track before penalizing the connection.

### HPACK Expansion
The `max_header_list_size` setting bounds the size of decoded HTTP headers. A malicious client could send heavily compressed headers (or a chain of `CONTINUATION` frames) that expand to consume massive amounts of memory. 

### First-Byte Deadline
HTTP/2 does not have a `header_read_timeout`. The server waits for a client preface and `SETTINGS` frame before arming the PING keep-alive. A client can negotiate `h2` and stay silent forever.

`FirstByteDeadline` wraps the connection in a timeout that fires if no data arrives. The deadline is disarmed by the first byte, allowing standard HTTP/2 keep-alive logic to take over.

## TLS Defenses

### Handshake Timeout (`handshake_timeout_ms`)
The TLS handshake executes inside the connection task. Without a timeout, a client could connect, begin the handshake, and stall. Because the connection limits are held during the handshake, this would allow an attacker to exhaust the connection budget. The handshake timeout ensures stalled connections are dropped.
