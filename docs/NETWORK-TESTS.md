# Isolated Linux network acceptance tests

Run `python3 scripts/test-network-interruption.py` after `cargo build --release`.
Add `--large` for the 2 GiB + 17 byte acceptance case. The default is 128 MiB.
The test needs Linux user/network namespaces, `ip`, `tc`, `unshare`, `nsenter`,
and Python 3 as development tools. It does not need sudo or alter host networking.

The launcher creates an unprivileged user namespace and an isolated network
namespace, verifies that it differs from the host, then creates a second network
namespace. Two actual daemons communicate across a veth pair on distinct IPv4
subnets. Both directions have 15 ms delay and 0.2% packet loss. Their local APIs
remain accessible inside their respective namespaces during a peer-network outage.

The test pairs once, starts the real CLI `push`, waits for the destination to
retain half the file, and changes both veth queues to 100% loss. It verifies
disconnect detection, preserves the partial file, restores the link and waits
for automatic reconnect and CLI resume. It never issues a second connect command
or invitation. Success requires a zero CLI exit, no checkpoint regression, and
matching destination size and complete SHA-256. Test tokens remain in memory;
private temporary state and all child processes are removed on exit.

The final current-binary default run transferred 134,217,728 bytes, detected
the outage after 67,502,080 bytes, retained a 67,567,616-byte durable
checkpoint, automatically reconnected and resumed to a matching SHA-256. Its
evidence is `target/validation/network-interruption-final.log` with exit code
`0`. The final current-binary 2 GiB + 17 byte run used the same harness and
completed with the same resume and checksum assertions. Its evidence is
`target/validation/network-interruption-final-large.log` with exit code `0`.

This is actual controlled Linux packet loss and recovery. It does not establish
Windows interoperability, a physical router restart, sleep/wake behavior,
restrictive-CGNAT hole punching, or an operating-system reboot. The separate
`scripts/test-linux-service.py` test covers a generated user systemd unit's
startup, process-crash restart with stable identity, and clean stop. A crash
restart is not an OS reboot.
