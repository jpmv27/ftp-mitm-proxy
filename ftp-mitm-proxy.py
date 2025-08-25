#!/usr/bin/env python3
"""
FTPS MITM proxy (control + PASV data MITM)
- Dual mode: systemd socket activation (--fd) OR CLI bind (--listen-addr/--listen-port)
- Control-channel MITM: terminates client TLS, opens TLS to server
- PASV data channels proxied (dynamic listeners). If PROT P active, both sides TLS-wrapped
- Proper TLS shutdown via unwrap() to avoid GnuTLS errors
- Optional upstream certificate verification suppression (--no-verify)
- Optional decrypted traffic logging (--log-traffic)
- Graceful shutdown on SIGINT/SIGTERM
"""
from __future__ import annotations
import argparse
import os
import socket
import ssl
import threading
import re
import sys
import signal
import time
from typing import Optional, Tuple

BUFFER_SIZE = 16 * 1024
ACCEPT_BACKLOG = 50

def parse_listen_socket(fd: int) -> socket.socket:
    """Duplicate FD and return a socket object that we own (so closing it won't break systemd)."""
    dup = os.dup(fd)
    try:
        s = socket.fromfd(dup, socket.AF_INET, socket.SOCK_STREAM)
    finally:
        try:
            os.close(dup)
        except Exception:
            pass
    return s

def determine_advertised_ip(server_host: str) -> str:
    """Return a local IP address to advertise for PASV if bound to 0.0.0.0."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        # use DNS resolution for server_host if needed
        try:
            ip = socket.gethostbyname(server_host)
        except Exception:
            ip = server_host
        sock.connect((ip, 9))
        local = sock.getsockname()[0]
        sock.close()
        return local
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return "127.0.0.1"

def safe_close(sock: Optional[socket.socket]):
    """Gracefully close an SSL or plain socket. For SSLSocket attempt unwrap() to send close_notify."""
    if sock is None:
        return
    try:
        if isinstance(sock, ssl.SSLSocket):
            try:
                # Attempt to send close_notify and get underlying socket
                underlying = sock.unwrap()
                if underlying:
                    try:
                        underlying.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        underlying.close()
                    except Exception:
                        pass
                    return
            except Exception:
                # unwrap failed; fallback to best-effort shutdown/close
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    sock.close()
                except Exception:
                    pass
                return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
    except Exception:
        try:
            sock.close()
        except Exception:
            pass

class FTPSMITMProxy:
    def __init__(self,
                 listen_sock: socket.socket,
                 server_host: str,
                 server_port: int,
                 certfile: str,
                 keyfile: str,
                 no_verify: bool = False,
                 log_traffic: bool = False):
        self.listen_sock = listen_sock
        self.server_host = server_host
        self.server_port = server_port
        self.certfile = certfile
        self.keyfile = keyfile
        self.no_verify = no_verify
        self.log_traffic = log_traffic

        self.running = True
        self.threads = []
        self.lock = threading.Lock()
        self.sessions = {}  # client_addr -> session state (dict)
        self.advertised_ip = None

        # make accept timeout small so shutdown is responsive
        try:
            self.listen_sock.settimeout(1.0)
        except Exception:
            pass

    def _log(self, direction: str, data: bytes):
        if not self.log_traffic:
            return
        try:
            sys.stdout.write(f"[{direction}] {data.decode('utf-8', errors='ignore').rstrip()}\n")
            sys.stdout.flush()
        except Exception:
            try:
                sys.stdout.write(f"[{direction}] <binary>\n")
                sys.stdout.flush()
            except Exception:
                pass

    def start(self):
        print("[+] FTPS MITM proxy starting")
        while self.running:
            try:
                client_sock, client_addr = self.listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self.handle_client, args=(client_sock, client_addr), daemon=True)
            t.start()
            with self.lock:
                self.threads.append(t)
        # join threads briefly
        self._join_threads(timeout=2)
        print("[*] Proxy main loop exiting")

    def stop(self):
        print("[*] stopping proxy...")
        self.running = False
        try:
            self.listen_sock.close()
        except Exception:
            pass
        self._join_threads(timeout=3)
        print("[*] stopped")

    def _join_threads(self, timeout=2):
        with self.lock:
            threads = list(self.threads)
            self.threads = []
        for t in threads:
            try:
                t.join(timeout=timeout)
            except Exception:
                pass

    def handle_client(self, client_sock: socket.socket, client_addr: Tuple[str,int]):
        session = {"prot_p": False}
        self.sessions[client_addr] = session
        client_ssl = None
        server_ssl = None
        server_raw = None
        try:
            if self.log_traffic:
                print(f"[+] client connected: {client_addr}")

            # Wrap client-side: act as TLS server
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            client_ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            client_ssl = client_ctx.wrap_socket(client_sock, server_side=True)

            # Resolve server_host (FQDN/IP) and connect
            try:
                addrinfo = socket.getaddrinfo(self.server_host, self.server_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                target = addrinfo[0][4]
            except Exception as e:
                print(f"[!] DNS resolution/connect info failed for server_host {self.server_host}: {e}")
                safe_close(client_ssl)
                return

            server_raw = socket.create_connection(target)

            # Wrap server-side: act as TLS client to server
            server_ctx = ssl.create_default_context()
            if self.no_verify:
                server_ctx.check_hostname = False
                server_ctx.verify_mode = ssl.CERT_NONE
            server_ssl = server_ctx.wrap_socket(server_raw, server_hostname=self.server_host)

            # Start control forwarding threads
            t1 = threading.Thread(target=self.forward_control, args=(client_ssl, server_ssl, "C->S", client_addr), daemon=True)
            t2 = threading.Thread(target=self.forward_control, args=(server_ssl, client_ssl, "S->C", client_addr), daemon=True)
            t1.start(); t2.start()
            # Wait for both to finish
            t1.join(); t2.join()
        except Exception as e:
            print(f"[!] handle_client error for {client_addr}: {e}")
        finally:
            safe_close(client_ssl or client_sock)
            safe_close(server_ssl or server_raw)
            self.sessions.pop(client_addr, None)

    def forward_control(self, src: socket.socket, dst: socket.socket, direction: str, client_addr: Tuple[str,int]):
        session = self.sessions.get(client_addr, {"prot_p": False})
        try:
            while self.running:
                try:
                    data = src.recv(BUFFER_SIZE)
                except OSError:
                    break
                if not data:
                    break

                # Log decrypted control channel
                self._log(direction, data)

                # Track PROT P/C
                if direction == "C->S":
                    cmd = data.strip().upper()
                    if cmd.startswith(b'PROT P'):
                        session["prot_p"] = True
                    elif cmd.startswith(b'PROT C'):
                        session["prot_p"] = False

                # If server -> client and PASV 227, rewrite IP if 0.0.0.0
                if direction == "S->C" and data.startswith(b'227'):
                    data = self._fix_pasv_227(data, session["prot_p"])

                # If client -> server and PORT (active), we log and pass through
                if direction == "C->S" and data.strip().upper().startswith(b'PORT'):
                    self._log("INFO", b"Active PORT intercepted (not MITMed)")

                try:
                    dst.sendall(data)
                except Exception:
                    break
        except Exception as e:
            print(f"[!] forward_control {direction} error: {e}")
        finally:
            # do not close counterpart here; main handler will close both sides
            pass

    def _fix_pasv_227(self, data: bytes, use_tls: bool) -> bytes:
        """
        If server returned 227 with 0,0,0,0,xx,yy — replace with proxy IP and spawn listener.
        Always starts a PASV listener and substitutes the returned port.
        """
        m = re.search(rb'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', data)
        if not m:
            return data
        server_port = int(m.group(5)) * 256 + int(m.group(6))
        proxy_port = self._start_pasv_listener(server_port, use_tls)
        # Determine advertise IP
        host_ip = self.listen_sock.getsockname()[0]
        if host_ip == '0.0.0.0' or host_ip == '::':
            if self.advertised_ip is None:
                self.advertised_ip = determine_advertised_ip(self.server_host)
            host_ip = self.advertised_ip
        parts = host_ip.split('.')
        p1 = proxy_port // 256
        p2 = proxy_port % 256
        new = f'({parts[0]},{parts[1]},{parts[2]},{parts[3]},{p1},{p2})'.encode()
        return re.sub(rb'\(.*\)', new, data)

    def _start_pasv_listener(self, server_port: int, use_tls: bool) -> int:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_ip = self.listen_sock.getsockname()[0]
        listener.bind((bind_ip, 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        t = threading.Thread(target=self._handle_pasv_connection, args=(listener, server_port, use_tls), daemon=True)
        t.start()
        with self.lock:
            self.threads.append(t)
        return port

    def _handle_pasv_connection(self, listener: socket.socket, server_port: int, use_tls: bool):
        client_data = None
        server_data = None
        try:
            client_data, _ = listener.accept()
            listener.close()
            # connect to server's data port
            server_raw = socket.create_connection((self.server_host, server_port))
            if use_tls:
                # Wrap both sides in TLS immediately (handshake)
                server_ctx = ssl.create_default_context()
                if self.no_verify:
                    server_ctx.check_hostname = False
                    server_ctx.verify_mode = ssl.CERT_NONE
                server_data = server_ctx.wrap_socket(server_raw, server_hostname=self.server_host)

                client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                client_ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
                client_data = client_ctx.wrap_socket(client_data, server_side=True)

                t1 = threading.Thread(target=self.forward_data_until_close, args=(client_data, server_data, "Data C->S"), daemon=True)
                t2 = threading.Thread(target=self.forward_data_until_close, args=(server_data, client_data, "Data S->C"), daemon=True)
                t1.start(); t2.start(); t1.join(); t2.join()
            else:
                server_data = server_raw
                t1 = threading.Thread(target=self.forward_data_until_close, args=(client_data, server_data, "Data C->S"), daemon=True)
                t2 = threading.Thread(target=self.forward_data_until_close, args=(server_data, client_data, "Data S->C"), daemon=True)
                t1.start(); t2.start(); t1.join(); t2.join()
        except Exception as e:
            print(f"[!] PASV data connection error: {e}")
        finally:
            safe_close(client_data)
            safe_close(server_data)

    def forward_data_until_close(self, src: socket.socket, dst: socket.socket, direction: str):
        try:
            while self.running:
                try:
                    chunk = src.recv(BUFFER_SIZE)
                except OSError:
                    break
                if not chunk:
                    break
                self._log(direction, chunk)
                try:
                    dst.sendall(chunk)
                except Exception:
                    break
        except Exception as e:
            print(f"[!] forward_data_until_close {direction} error: {e}")
        finally:
            safe_close(src)
            safe_close(dst)

def main():
    p = argparse.ArgumentParser(description="FTPS MITM proxy (control + PASV data MITM)")
    p.add_argument("--fd", type=int, default=None, help="systemd listen FD (e.g. 3)")
    p.add_argument("--listen-addr", type=str, default=None, help="bind address (if not using --fd)")
    p.add_argument("--listen-port", type=int, default=None, help="bind port (if not using --fd)")
    p.add_argument("--server-host", type=str, required=True, help="upstream FTP server (FQDN or IP)")
    p.add_argument("--server-port", type=int, default=21, help="upstream FTP port")
    p.add_argument("--certfile", type=str, required=True, help="MITM certificate (PEM)")
    p.add_argument("--keyfile", type=str, required=True, help="MITM private key (PEM)")
    p.add_argument("--no-verify", action="store_true", help="do not verify upstream server cert")
    p.add_argument("--log-traffic", action="store_true", help="log decrypted traffic")
    args = p.parse_args()

    # Prepare listen socket
    listen_sock = None
    if args.fd is not None:
        listen_sock = parse_listen_socket(args.fd)
    elif args.listen_addr and args.listen_port:
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind((args.listen_addr, args.listen_port))
        listen_sock.listen(ACCEPT_BACKLOG)
    else:
        print("Must supply either --fd or both --listen-addr and --listen-port")
        sys.exit(1)

    proxy = FTPSMITMProxy(listen_sock=listen_sock,
                          server_host=args.server_host,
                          server_port=args.server_port,
                          certfile=args.certfile,
                          keyfile=args.keyfile,
                          no_verify=args.no_verify,
                          log_traffic=args.log_traffic)

    def _sig_handler(signum, frame):
        print("[*] signal received, shutting down...")
        proxy.stop()
        # small grace period
        time.sleep(0.1)
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    proxy.start()

if __name__ == "__main__":
    main()

