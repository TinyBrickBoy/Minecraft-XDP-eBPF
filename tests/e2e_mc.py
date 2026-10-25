#!/usr/bin/env python3
"""Fake minecraft servers and clients for tests/e2e_docker.sh.

Servers: java-server, bedrock-server, echo-server (a non-minecraft service).
Clients exit 0 on the expected outcome, 1 otherwise:
  status          java status + ping round trip works
  player SECS     java login, then echo traffic for SECS seconds without a gap
  garbage         a non-minecraft TCP stream is NOT answered (dropped)
  echo            plain TCP echo works (unprotected service)
  bedrock-ping    RakNet unconnected ping is answered with a pong
  bedrock-session SECS  RakNet open connection handshake, then frames
  bedrock-garbage a non-RakNet datagram is NOT answered (dropped)
"""
import socket
import struct
import sys
import threading
import time

MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
PROTOCOL = 767  # 1.21


def varint(value):
    value &= 0xFFFFFFFF
    out = b""
    while True:
        if value & ~0x7F == 0:
            return out + bytes([value])
        out += bytes([(value & 0x7F) | 0x80])
        value >>= 7


def read_varint(sock):
    value = 0
    for i in range(5):
        byte = sock.recv(1)
        if not byte:
            raise EOFError
        value |= (byte[0] & 0x7F) << (7 * i)
        if not byte[0] & 0x80:
            return value
    raise ValueError("varint too long")


def packet(body):
    return varint(len(body)) + body


def handshake(host, port, intention):
    return packet(b"\x00" + varint(PROTOCOL) + varint(len(host)) + host.encode()
                  + struct.pack(">H", port) + varint(intention))


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


# ---------------------------------------------------------------- servers

def java_conn(conn):
    try:
        length = read_varint(conn)
        body = recv_exact(conn, length)
        if body[0] != 0x00 or length > 300:
            conn.sendall(b"BAD")
            return
        intention = body[-1]
        if intention == 1:
            read_varint(conn), recv_exact(conn, 1)  # status request
            status = b'{"version":{"name":"1.21","protocol":767},"description":"e2e"}'
            conn.sendall(packet(b"\x00" + varint(len(status)) + status))
            length = read_varint(conn)
            conn.sendall(packet(recv_exact(conn, length)))  # pong = ping
            return
        length = read_varint(conn)
        recv_exact(conn, length)  # login start
        while True:  # "game": echo everything
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data)
    except (EOFError, OSError, ValueError, IndexError):
        pass
    finally:
        conn.close()


def serve_tcp(host, port, handler):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(128)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def echo_conn(conn):
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()


def bedrock_server(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    guid = struct.pack(">Q", 0x1234)
    info = b"MCPE;e2e;712;1.21.0;0;10;1234;e2e;Survival;1;19132;19133;"
    while True:
        data, addr = sock.recvfrom(2048)
        pid = data[0]
        if pid in (0x01, 0x02):
            sock.sendto(b"\x1c" + data[1:9] + guid + MAGIC + struct.pack(">H", len(info)) + info, addr)
        elif pid == 0x05:
            sock.sendto(b"\x06" + MAGIC + guid + b"\x00" + struct.pack(">H", 1400), addr)
        elif pid == 0x07:
            sock.sendto(b"\x08" + MAGIC + guid + b"\x04" + bytes(6) + struct.pack(">H", 1400) + b"\x00", addr)
        elif (pid & 0xF0) == 0x80 or pid in (0xA0, 0xC0):
            sock.sendto(data, addr)
        else:
            sock.sendto(b"BAD", addr)


# ---------------------------------------------------------------- clients

def status(host, port):
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(handshake(host, port, 1) + b"\x01\x00")
        read_varint(s)
        assert read_varint(s) == 0
        json = recv_exact(s, read_varint(s))
        assert b'"version"' in json
        s.sendall(packet(b"\x01" + struct.pack(">q", 42)))
        read_varint(s)
        assert recv_exact(s, 9) == b"\x01" + struct.pack(">q", 42)
    return True


def player(host, port, secs):
    with socket.create_connection((host, port), timeout=3) as s:
        login = packet(b"\x00" + varint(6) + b"Tester" + bytes(16))
        s.sendall(handshake(host, port, 2) + login)
        end = time.time() + secs
        n = 0
        while time.time() < end:
            msg = b"tick%06d" % n
            s.sendall(msg)
            if recv_exact(s, len(msg)) != msg:
                return False
            n += 1
            time.sleep(0.5)
    return True


def garbage(host, port):
    try:
        with socket.create_connection((host, port), timeout=2) as s:
            # long enough that the fake server reads a full bogus "packet"
            # and answers BAD when nothing filters it
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n" + b"X" * 200)
            return not s.recv(16)  # any answer means it got through
    except (socket.timeout, ConnectionError):
        return True


def echo(host, port):
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(b"hello")
        return recv_exact(s, 5) == b"hello"


def udp_exchange(sock, data, timeout=2):
    sock.settimeout(timeout)
    sock.send(data)
    try:
        return sock.recv(2048)
    except socket.timeout:
        return None


def bedrock_ping(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, port))
        reply = udp_exchange(s, b"\x01" + struct.pack(">Q", 1) + MAGIC + struct.pack(">Q", 7))
        return bool(reply) and reply[0] == 0x1C and reply[17:33] == MAGIC


def bedrock_session(host, port, secs):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, port))
        r = udp_exchange(s, b"\x05" + MAGIC + b"\x0b" + bytes(1000))
        if not r or r[0] != 0x06:
            return False
        r = udp_exchange(s, b"\x07" + MAGIC + b"\x04" + bytes(6) + struct.pack(">H", 1400) + struct.pack(">Q", 7))
        if not r or r[0] != 0x08:
            return False
        end = time.time() + secs
        n = 0
        while time.time() < end:
            frame = b"\x84" + struct.pack(">I", n)[1:] + b"payload"
            if udp_exchange(s, frame) != frame:
                return False
            n += 1
            time.sleep(0.5)
    return True


def bedrock_garbage(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, port))
        return udp_exchange(s, b"\x99junkjunkjunk") is None


def main():
    cmd, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    extra = [float(a) for a in sys.argv[4:]]
    if cmd == "java-server":
        serve_tcp(host, port, java_conn)
    elif cmd == "echo-server":
        serve_tcp(host, port, echo_conn)
    elif cmd == "bedrock-server":
        bedrock_server(host, port)
    else:
        fn = {"status": status, "player": player, "garbage": garbage, "echo": echo,
              "bedrock-ping": bedrock_ping, "bedrock-session": bedrock_session,
              "bedrock-garbage": bedrock_garbage}[cmd]
        try:
            ok = fn(host, port, *extra)
        except Exception as e:  # noqa: BLE001 - any failure is a test failure
            print(f"{cmd}: {e!r}", file=sys.stderr)
            ok = False
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
