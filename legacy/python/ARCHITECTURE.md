# OpenGate architecture

## Current direct-connect MVP

```text
Controller PC                         Host PC
-------------                         -------
ssh client                            OpenSSH Server (sshd)
    |                                      ^
127.0.0.1:2222                             | 127.0.0.1:22
    |                                      |
OpenGate controller  <--- TCP --->   OpenGate host
         |                                |
 saved device secret                 paired-controller table
```

The OpenGate connection is an authenticated transport. After authentication, bytes are forwarded to local OpenSSH. SSH remains responsible for user authentication, encryption, host keys, terminal behavior, file transfer, SCP/SFTP, and administrator/root policy.

## Pairing

1. Host generates a random 256-bit bootstrap secret and an expiry.
2. Token contains host identity metadata, reachable candidate addresses, bootstrap secret, and expiry.
3. Controller creates a random controller ID.
4. Host sends a fresh random challenge.
5. Controller proves knowledge of the bootstrap secret with HMAC-SHA-256.
6. Both sides derive the same long-term per-controller secret.
7. Host stores that controller secret and invalidates the bootstrap token.
8. Controller stores its device record locally.

The bootstrap token is therefore single-use.

## Later authentication

1. Host sends a new 256-bit challenge.
2. Controller sends HMAC-SHA-256(challenge, saved device secret).
3. Host compares it with its stored secret.
4. If valid, it opens a connection to the loopback SSH server.

A captured proof cannot simply be replayed because every connection uses a new challenge.

## Why the first build uses OpenSSH

Implementing another privileged shell protocol would duplicate authentication, PTY handling, SFTP/SCP, key management, terminal behavior, and operating-system privilege policy. Using the system OpenSSH server gives Windows and Linux the same well-understood administration surface while OpenGate focuses on pairing and transport.

## NAT/CGNAT roadmap

Universal "no port forwarding" reachability needs more than the two private machines. The recommended production path is:

1. Both peers create outbound connections to a tiny authenticated rendezvous service.
2. Each peer discovers its public UDP mapping.
3. Rendezvous exchanges short-lived endpoint candidates and signed pairing metadata.
4. Both peers simultaneously attempt UDP hole punching.
5. A direct QUIC connection is established if the NATs permit it.
6. OpenSSH bytes flow only over the direct encrypted QUIC path.
7. On symmetric/restrictive NAT, either report "direct connection unavailable" or use an explicitly enabled relay fallback.

A rendezvous-only service can coordinate the direct attempt, but it cannot make every NAT combination work. A relay is the only generic fallback for networks that refuse a usable peer-to-peer path.

## Production privilege model

OpenGate should never silently elevate a controller. The target OS remains authoritative:

- Linux users obtain root only through existing SSH/root/sudo policy.
- Windows users obtain administrator rights only through an already-authorized Windows account and Windows OpenSSH policy.

This keeps privilege decisions auditable and prevents the transport layer from becoming a separate privilege-escalation mechanism.
