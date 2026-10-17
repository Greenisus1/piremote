#!/usr/bin/env python3
# piws.py - DNS-independent ProxyCommand for ssh over a Cloudflare tunnel.
# Resolves the hostname via DNS-over-HTTPS to IP-literal resolvers (immune to
# DNS hijacking), then speaks cloudflared's websocket protocol to the edge.
# Usage: piws.py <hostname>   (bridges stdin/stdout to the tunnel)
import sys, socket, ssl, os, base64, struct, select, json
from urllib.request import Request, urlopen

HOST = sys.argv[1] if len(sys.argv) > 1 else "ssh.crunchbytes.dpdns.org"
DOH = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]

def resolve(host):
    for ns in DOH:
        try:
            req = Request("https://%s/dns-query?name=%s&type=A" % (ns, host),
                          headers={"accept": "application/dns-json"})
            data = json.load(urlopen(req, timeout=6))
            ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
            if ips:
                return ips
        except Exception:
            continue
    sys.stderr.write("piws: DoH resolution failed\n")
    sys.exit(1)

def ws_connect(host):
    ips = resolve(host)
    last = None
    for ip in ips:
        try:
            raw = socket.create_connection((ip, 443), timeout=10)
            ctx = ssl.create_default_context()
            return ctx.wrap_socket(raw, server_hostname=host)
        except Exception as e:
            last = e
    sys.stderr.write("piws: edge connect failed: %s\n" % last)
    sys.exit(1)

def ws_handshake(tls, host):
    key = base64.b64encode(os.urandom(16)).decode()
    req = ("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\nUser-Agent: cloudflared\r\n\r\n" % (host, key))
    tls.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = tls.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    if b" 101" not in head.split(b"\r\n", 1)[0]:
        sys.stderr.write("piws: handshake rejected: %s\n" % head.split(b"\r\n", 1)[0].decode(errors="replace"))
        sys.exit(1)
    return rest

def ws_send(tls, opcode, payload):
    n = len(payload)
    if n < 126:
        hdr = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
    elif n < 65536:
        hdr = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    data = hdr + mask + masked
    while data:
        try:
            sent = tls.send(data)
            data = data[sent:]
        except ssl.SSLWantWriteError:
            select.select([], [tls], [])

class Reader:
    def __init__(self, tls, initial):
        self.tls = tls
        self.buf = bytearray(initial)
    def _fill(self, n):
        while len(self.buf) < n:
            try:
                chunk = self.tls.recv(65536)
            except (ssl.SSLWantReadError, BlockingIOError):
                return False
            if not chunk:
                raise EOFError
            self.buf += chunk
        return True
    def frame(self):
        if not self._fill(2):
            return None
        b0, b1 = self.buf[0], self.buf[1]
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        idx = 2
        if ln == 126:
            if not self._fill(idx + 2): return None
            ln = struct.unpack("!H", self.buf[idx:idx+2])[0]; idx += 2
        elif ln == 127:
            if not self._fill(idx + 8): return None
            ln = struct.unpack("!Q", self.buf[idx:idx+8])[0]; idx += 8
        mask = b""
        if masked:
            if not self._fill(idx + 4): return None
            mask = bytes(self.buf[idx:idx+4]); idx += 4
        if not self._fill(idx + ln):
            return None
        payload = bytes(self.buf[idx:idx+ln])
        del self.buf[:idx+ln]
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload

def main():
    tls = ws_connect(HOST)
    rest = ws_handshake(tls, HOST)
    tls.setblocking(False)
    rdr = Reader(tls, rest)
    inf = sys.stdin.buffer
    outf = sys.stdout.buffer
    while True:
        r, _, _ = select.select([inf, tls], [], [])
        if tls in r:
            try:
                while True:
                    fr = rdr.frame()
                    if fr is None:
                        break
                    opcode, payload = fr
                    if opcode in (0, 1, 2):
                        outf.write(payload); outf.flush()
                    elif opcode == 8:
                        return
                    elif opcode == 9:
                        ws_send(tls, 10, payload)
            except (EOFError, ssl.SSLError, OSError):
                return
        if inf in r:
            data = os.read(0, 32768)
            if not data:
                try:
                    ws_send(tls, 8, b"")
                except Exception:
                    pass
                return
            ws_send(tls, 2, data)

main()
