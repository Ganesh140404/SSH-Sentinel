"""
Multi-port honeypot engine.
Services: SSH (paramiko fake shell), FTP, HTTP, Telnet, MySQL, Redis, SMTP
All services are completely fake – no real shell, no real data.
"""
import os
import socket
import struct
import threading
import logging
import textwrap
import uuid
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import paramiko

from config import Config
from honeypot_logger import init_db, log_event, is_banned

logger = logging.getLogger("sentinel.core")

# ── Rate limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self, max_per_ip: int = Config.MAX_CONN_PER_IP, window: int = 60):
        self._counts: dict = defaultdict(list)
        self._lock = threading.Lock()
        self.max_per_ip = max_per_ip
        self.window = window

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            self._counts[ip] = [t for t in self._counts[ip] if now - t < self.window]
            if len(self._counts[ip]) >= self.max_per_ip:
                return False
            self._counts[ip].append(now)
            return True


_rate_limiter = RateLimiter()


# ── Fake shell ────────────────────────────────────────────────────────────────

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
)

FAKE_SHADOW = (
    "root:$6$rounds=5000$FAKEHASHEDVALUE$:19000:0:99999:7:::\n"
    "ubuntu:$6$rounds=5000$ANOTHERFAKEHASH$:19100:0:99999:7:::\n"
)

FAKE_HISTORY = (
    "  1  sudo apt update\n"
    "  2  ls -la\n"
    "  3  cat /etc/hostname\n"
    "  4  ps aux\n"
    "  5  netstat -tulpn\n"
    "  6  exit\n"
)

FAKE_PS = (
    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    "root         1  0.0  0.1  16952  2700 ?        Ss   03:12   0:01 /sbin/init\n"
    "root       423  0.0  0.2  72296  4360 ?        Ss   03:12   0:00 /usr/sbin/sshd -D\n"
    "root       512  0.0  0.2  28356  5460 ?        Ss   03:13   0:00 /usr/sbin/cron -f\n"
    "ubuntu    1024  0.0  0.1  21484  2440 pts/0    Ss   04:05   0:00 -bash\n"
    "ubuntu    1031  0.0  0.1  38384  3340 pts/0    R+   04:05   0:00 ps aux\n"
)

FAKE_NETSTAT = (
    "Active Internet connections (only servers)\n"
    "Proto Recv-Q Send-Q Local Address    Foreign Address  State\n"
    "tcp        0      0 0.0.0.0:22       0.0.0.0:*        LISTEN\n"
    "tcp        0      0 0.0.0.0:80       0.0.0.0:*        LISTEN\n"
    "tcp6       0      0 :::22            :::*             LISTEN\n"
)

FAKE_IFCONFIG = (
    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n"
    "        inet 172.31.14.22  netmask 255.255.240.0  broadcast 172.31.15.255\n"
    "        inet6 fe80::8af:d1ff:fe8b:3c4a  prefixlen 64  scopeid 0x20<link>\n"
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
    "        inet 127.0.0.1  netmask 255.0.0.0\n"
)

FAKE_UNAME = "Linux ip-172-31-14-22 5.15.0-1034-aws #38~20.04.1-Ubuntu SMP x86_64 GNU/Linux\n"

FAKE_DIR_ENTRIES = [
    "total 36",
    "drwxr-xr-x 5 ubuntu ubuntu 4096 Jan 10 12:44 .",
    "drwxr-xr-x 3 root   root   4096 Jan  9 03:12 ..",
    "-rw------- 1 ubuntu ubuntu  220 Jan  9 03:12 .bash_logout",
    "-rw-r--r-- 1 ubuntu ubuntu 3526 Jan  9 03:12 .bashrc",
    "-rw-r--r-- 1 ubuntu ubuntu  807 Jan  9 03:12 .profile",
    "drwx------ 2 ubuntu ubuntu 4096 Jan 10 12:30 .ssh",
    "-rw-rw-r-- 1 ubuntu ubuntu  512 Jan 10 12:44 notes.txt",
    "drwxrwxr-x 2 ubuntu ubuntu 4096 Jan 10 12:44 scripts",
]

FAKE_CRONTAB = (
    "# Edit this file to introduce tasks to be run by cron.\n"
    "# m h  dom mon dow   command\n"
    "*/5 * * * * /usr/bin/python3 /home/ubuntu/scripts/monitor.py\n"
    "0 2 * * * /home/ubuntu/scripts/backup.sh\n"
)


class FakeShell:
    """Stateful fake shell per session. Never executes anything."""

    PROMPT = b"ubuntu@ip-172-31-14-22:~$ "

    def __init__(self, ip: str, session_id: str):
        self.ip = ip
        self.session_id = session_id
        self.cwd = "/home/ubuntu"
        self.env = {
            "HOME": "/home/ubuntu", "USER": "ubuntu",
            "HOSTNAME": "ip-172-31-14-22", "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": "/home/ubuntu",
        }

    def banner(self) -> bytes:
        return (
            b"\r\nWelcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-1034-aws x86_64)\r\n\r\n"
            b" * Documentation:  https://help.ubuntu.com\r\n"
            b" * Management:     https://landscape.canonical.com\r\n\r\n"
            b"  System information as of " + time.strftime("%a %b %d %H:%M:%S UTC %Y").encode() + b"\r\n\r\n"
            b"  System load:  0.08              Processes:             98\r\n"
            b"  Usage of /:   12.3% of 29.4GB   Users logged in:       0\r\n"
            b"  Memory usage: 23%               IPv4 address for eth0: 172.31.14.22\r\n\r\n"
        )

    def process(self, raw: str) -> bytes:
        cmd = raw.strip()
        if not cmd:
            return self.PROMPT

        # Log command
        log_event("ssh", self.ip, event_type="command", payload=cmd, session_id=self.session_id)

        # Detect download attempts and log URL
        for dl_cmd in ("wget", "curl"):
            if cmd.startswith(dl_cmd):
                parts = cmd.split()
                url = next((p for p in parts if p.startswith("http")), cmd)
                log_event("ssh", self.ip, event_type="download_attempt", payload=url, session_id=self.session_id)

        response = self._dispatch(cmd)
        out = response.replace("\n", "\r\n").encode(errors="replace")
        return out + self.PROMPT

    def _dispatch(self, cmd: str) -> str:
        base = cmd.split()[0] if cmd.split() else ""
        args = cmd.split()[1:] if len(cmd.split()) > 1 else []
        full_arg = " ".join(args)

        # exit / logout
        if base in ("exit", "logout", "quit"):
            return "logout\r\n"

        # ls
        if base == "ls":
            if "-la" in args or "-al" in args or "-a" in args:
                return "\n".join(FAKE_DIR_ENTRIES) + "\n"
            return "notes.txt  scripts\n"

        # pwd
        if base == "pwd":
            return self.cwd + "\n"

        # cd (stateful but fake)
        if base == "cd":
            if not args or full_arg in ("~", "/home/ubuntu"):
                self.cwd = "/home/ubuntu"
            elif full_arg == "/":
                self.cwd = "/"
            elif full_arg.startswith("/"):
                self.cwd = full_arg
            else:
                self.cwd = self.cwd.rstrip("/") + "/" + full_arg
            return ""

        # whoami
        if base == "whoami":
            return "ubuntu\n"

        # id
        if base == "id":
            return "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),27(sudo)\n"

        # uname
        if base == "uname":
            if "-r" in args:
                return "5.15.0-1034-aws\n"
            return FAKE_UNAME

        # hostname
        if base == "hostname":
            return "ip-172-31-14-22\n"

        # cat
        if base == "cat":
            target = full_arg
            fake_files = {
                "/etc/passwd":    FAKE_PASSWD,
                "/etc/shadow":    FAKE_SHADOW,
                "/etc/hostname":  "ip-172-31-14-22\n",
                "/etc/os-release": 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\n',
                "/proc/version":  "Linux version 5.15.0-1034-aws (gcc 9.4.0) #38~20.04.1-Ubuntu SMP\n",
                ".bashrc":        "# .bashrc\nexport PS1='\\u@\\h:\\w\\$ '\nexport PATH=$PATH:/usr/local/bin\n",
                "notes.txt":      "TODO: update deployment scripts\nCheck cron jobs\n",
                "/etc/crontab":   FAKE_CRONTAB,
            }
            return fake_files.get(target, f"cat: {target}: No such file or directory\n")

        # ps
        if base == "ps":
            return FAKE_PS

        # netstat / ss
        if base in ("netstat", "ss"):
            return FAKE_NETSTAT

        # ifconfig / ip
        if base == "ifconfig":
            return FAKE_IFCONFIG
        if base == "ip":
            if args and args[0] in ("addr", "a", "address"):
                return FAKE_IFCONFIG
            return f"Object \"{full_arg}\" is unknown, try \"ip help\".\n"

        # history
        if base == "history":
            return FAKE_HISTORY

        # env / printenv
        if base in ("env", "printenv"):
            return "\n".join(f"{k}={v}" for k, v in self.env.items()) + "\n"

        # echo
        if base == "echo":
            text = " ".join(args)
            for k, v in self.env.items():
                text = text.replace(f"${k}", v).replace(f"${{{k}}}", v)
            return text + "\n"

        # sudo
        if base == "sudo":
            return "[sudo] password for ubuntu: \nSorry, try again.\n[sudo] password for ubuntu: \nSudo: 3 incorrect password attempts\n"

        # su
        if base == "su":
            return "Password: \nsu: Authentication failure\n"

        # python / python3
        if base in ("python", "python3", "python2"):
            return "Python 3.8.10 (default, Nov 14 2022, 12:59:47)\n[GCC 9.4.0] on linux\nType \"help\" for details.\n>>> \n"

        # perl
        if base == "perl":
            return ""

        # wget
        if base == "wget":
            url = next((a for a in args if a.startswith("http")), "unknown")
            return (f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
                    f"Resolving host... failed: Name or service not known.\n"
                    f"wget: unable to resolve host address\n")

        # curl
        if base == "curl":
            url = next((a for a in args if a.startswith("http")), "unknown")
            return f"curl: (6) Could not resolve host: {url.split('/')[2] if '/' in url else url}\n"

        # chmod / chown / mkdir / touch / rm
        if base in ("chmod", "chown", "touch", "mkdir"):
            return ""
        if base == "rm":
            return ""

        # find
        if base == "find":
            return ""

        # service / systemctl
        if base in ("service", "systemctl"):
            return "Failed to connect to bus: No such file or directory\n"

        # crontab
        if base == "crontab":
            return FAKE_CRONTAB

        # dpkg / apt
        if base in ("dpkg", "apt", "apt-get", "yum", "dnf"):
            return "E: Could not open lock file - open (13: Permission denied)\n"

        # passwd
        if base == "passwd":
            return "passwd: Authentication token manipulation error\npasswd: password unchanged\n"

        # Default: command not found
        return f"-bash: {base}: command not found\n"


# ── Base service ──────────────────────────────────────────────────────────────

class BaseHoneypot:
    service_name = "base"

    def __init__(self, port: int):
        self.port = port
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._listen, daemon=True, name=self.service_name)
        self._thread.start()
        logger.info("%s honeypot listening on port %d", self.service_name.upper(), self.port)

    def stop(self):
        self._stop.set()

    def _listen(self):
        raise NotImplementedError

    @staticmethod
    def _safe_recv(sock: socket.socket, size: int = 4096) -> bytes:
        try:
            return sock.recv(size)
        except Exception:
            return b""

    @staticmethod
    def _safe_send(sock: socket.socket, data: bytes):
        try:
            sock.sendall(data)
        except Exception:
            pass


# ── SSH Honeypot ──────────────────────────────────────────────────────────────

def _ensure_host_key() -> paramiko.RSAKey:
    path = Config.HOST_KEY_PATH
    if os.path.exists(path):
        return paramiko.RSAKey.from_private_key_file(path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    logger.info("Generated new SSH host key at %s", path)
    return key


HOST_KEY = None  # loaded lazily


class _SSHInterface(paramiko.ServerInterface):
    def __init__(self, ip: str, session_id: str):
        self.ip = ip
        self.session_id = session_id
        self.shell_event = threading.Event()
        self.exec_command = None

    def check_channel_request(self, kind, chanid):
        if kind in ("session",):
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_event("ssh", self.ip, dest_port=Config.SSH_PORT,
                  event_type="auth_attempt", username=username,
                  password=password, session_id=self.session_id)
        # Always succeed so attacker gets fake shell interaction
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        fp = key.get_fingerprint().hex()
        log_event("ssh", self.ip, dest_port=Config.SSH_PORT,
                  event_type="auth_attempt_pubkey", username=username,
                  payload=fp, session_id=self.session_id)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.shell_event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode(errors="replace")
        self.shell_event.set()
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True


def _handle_ssh_client(client_sock: socket.socket, addr: tuple):
    global HOST_KEY
    ip, port = addr[0], addr[1]
    session_id = uuid.uuid4().hex[:12]

    log_event("ssh", ip, source_port=port, dest_port=Config.SSH_PORT,
              event_type="connection", session_id=session_id)

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = Config.SSH_BANNER
        transport.add_server_key(HOST_KEY)

        server_iface = _SSHInterface(ip, session_id)
        transport.start_server(server=server_iface)

        chan = transport.accept(20)
        if chan is None:
            return

        server_iface.shell_event.wait(10)

        shell = FakeShell(ip, session_id)

        # Handle exec (non-interactive) command
        if server_iface.exec_command:
            cmd_resp = shell.process(server_iface.exec_command)
            chan.sendall(cmd_resp.replace(shell.PROMPT, b""))
            chan.send_exit_status(0)
            chan.close()
            return

        # Interactive shell
        chan.sendall(shell.banner())
        chan.sendall(shell.PROMPT)

        buf = b""
        while transport.is_active():
            try:
                data = chan.recv(256)
            except Exception:
                break
            if not data:
                break

            # Echo typed characters back (raw terminal)
            chan.sendall(data)

            for byte in data:
                b = bytes([byte])
                if b in (b"\r", b"\n"):
                    chan.sendall(b"\r\n")
                    cmd_text = buf.decode(errors="replace").strip()
                    buf = b""
                    if cmd_text.lower() in ("exit", "logout", "quit"):
                        chan.sendall(b"logout\r\n")
                        chan.close()
                        return
                    if cmd_text:
                        response = shell.process(cmd_text)
                        chan.sendall(response)
                    else:
                        chan.sendall(shell.PROMPT)
                elif byte == 127 or byte == 8:  # backspace
                    if buf:
                        buf = buf[:-1]
                        chan.sendall(b"\b \b")
                else:
                    buf += b

    except Exception as exc:
        logger.debug("SSH session error %s: %s", ip, exc)
    finally:
        if transport:
            transport.close()


class SSHHoneypot(BaseHoneypot):
    service_name = "ssh"

    def _listen(self):
        global HOST_KEY
        HOST_KEY = _ensure_host_key()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(50)
        srv.settimeout(1)

        while not self._stop.is_set():
            try:
                client_sock, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            ip = addr[0]
            if is_banned(ip) or not _rate_limiter.allow(ip):
                client_sock.close()
                continue

            t = threading.Thread(target=_handle_ssh_client,
                                  args=(client_sock, addr), daemon=True)
            t.start()

        srv.close()


# ── FTP Honeypot ──────────────────────────────────────────────────────────────

FAKE_FTP_LISTING = (
    "drwxr-xr-x    2 ftp      ftp          4096 Jan 10 12:00 pub\r\n"
    "-rw-r--r--    1 ftp      ftp          1234 Jan 10 11:00 README.txt\r\n"
)


def _handle_ftp_client(client_sock: socket.socket, addr: tuple):
    ip, port = addr
    session_id = uuid.uuid4().hex[:12]
    log_event("ftp", ip, source_port=port, dest_port=Config.FTP_PORT,
              event_type="connection", session_id=session_id)

    try:
        client_sock.settimeout(30)
        BaseHoneypot._safe_send(client_sock, f"{Config.FTP_BANNER}\r\n".encode())

        username = None
        data_port_open = False

        while True:
            line = b""
            while True:
                b = BaseHoneypot._safe_recv(client_sock, 1)
                if not b or b == b"\n":
                    break
                if b != b"\r":
                    line += b

            if not line:
                break

            cmd_line = line.decode(errors="replace").strip()
            if not cmd_line:
                continue

            parts = cmd_line.split(None, 1)
            cmd   = parts[0].upper()
            arg   = parts[1] if len(parts) > 1 else ""

            if cmd == "USER":
                username = arg
                BaseHoneypot._safe_send(client_sock, b"331 Please specify the password.\r\n")

            elif cmd == "PASS":
                log_event("ftp", ip, source_port=port, dest_port=Config.FTP_PORT,
                          event_type="auth_attempt", username=username,
                          password=arg, session_id=session_id)
                BaseHoneypot._safe_send(client_sock, b"230 Login successful.\r\n")

            elif cmd == "SYST":
                BaseHoneypot._safe_send(client_sock, b"215 UNIX Type: L8\r\n")

            elif cmd == "FEAT":
                BaseHoneypot._safe_send(client_sock,
                    b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")

            elif cmd == "PWD":
                BaseHoneypot._safe_send(client_sock, b'257 "/" is the current directory\r\n')

            elif cmd in ("LIST", "NLST"):
                log_event("ftp", ip, source_port=port, dest_port=Config.FTP_PORT,
                          event_type="directory_list", session_id=session_id)
                BaseHoneypot._safe_send(client_sock, b"150 Here comes the directory listing.\r\n")
                BaseHoneypot._safe_send(client_sock, FAKE_FTP_LISTING.encode())
                BaseHoneypot._safe_send(client_sock, b"226 Directory send OK.\r\n")

            elif cmd == "RETR":
                log_event("ftp", ip, source_port=port, dest_port=Config.FTP_PORT,
                          event_type="file_download_attempt", payload=arg, session_id=session_id)
                BaseHoneypot._safe_send(client_sock,
                    b"550 Failed to open file.\r\n")

            elif cmd == "STOR":
                log_event("ftp", ip, source_port=port, dest_port=Config.FTP_PORT,
                          event_type="file_upload_attempt", payload=arg, session_id=session_id)
                BaseHoneypot._safe_send(client_sock,
                    b"553 Could not create file.\r\n")

            elif cmd == "PASV":
                BaseHoneypot._safe_send(client_sock,
                    b"227 Entering Passive Mode (172,31,14,22,195,149).\r\n")

            elif cmd in ("TYPE", "MODE", "STRU"):
                BaseHoneypot._safe_send(client_sock, b"200 OK.\r\n")

            elif cmd in ("QUIT", "BYE"):
                BaseHoneypot._safe_send(client_sock, b"221 Goodbye.\r\n")
                break

            else:
                log_event("ftp", ip, source_port=port, dest_port=Config.FTP_PORT,
                          event_type="command", payload=cmd_line, session_id=session_id)
                BaseHoneypot._safe_send(client_sock,
                    f"502 Command not implemented: {cmd}\r\n".encode())

    except Exception as exc:
        logger.debug("FTP session error %s: %s", ip, exc)
    finally:
        client_sock.close()


class FTPHoneypot(BaseHoneypot):
    service_name = "ftp"

    def _listen(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(50)
        srv.settimeout(1)

        while not self._stop.is_set():
            try:
                client_sock, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            ip = addr[0]
            if is_banned(ip) or not _rate_limiter.allow(ip):
                client_sock.close()
                continue

            threading.Thread(target=_handle_ftp_client,
                             args=(client_sock, addr), daemon=True).start()
        srv.close()


# ── HTTP Honeypot ─────────────────────────────────────────────────────────────

_HTTP_LOGIN_PAGE = textwrap.dedent("""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>cPanel Login</title>
  <style>
    body{background:#1e2436;color:#eee;font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .box{background:#283045;padding:40px;border-radius:8px;width:340px;box-shadow:0 4px 20px rgba(0,0,0,.4)}
    h2{text-align:center;color:#00c9ff;margin-bottom:24px}
    input{width:100%;padding:10px;margin:8px 0;border:none;border-radius:4px;background:#1e2436;color:#eee;box-sizing:border-box}
    button{width:100%;padding:12px;background:#00c9ff;border:none;border-radius:4px;color:#000;font-weight:bold;cursor:pointer;margin-top:12px}
    .footer{text-align:center;font-size:11px;margin-top:14px;color:#888}
  </style>
</head>
<body>
  <div class="box">
    <h2>cPanel Login</h2>
    <form method="POST">
      <input name="user" type="text" placeholder="Username" autocomplete="off">
      <input name="pass" type="password" placeholder="Password">
      <button type="submit">Log in</button>
    </form>
    <div class="footer">cPanel &amp; WHM 114.0</div>
  </div>
</body>
</html>
""").encode()

_HTTP_DENIED = b"<html><body><h2>Login Failed</h2><p>Invalid credentials.</p></body></html>"

_FAKE_PAGES = {
    "/phpmyadmin": b"<html><body><h2>phpMyAdmin 5.2.0</h2><form method='POST'><input name='pma_username' placeholder='Username'><input name='pma_password' type='password' placeholder='Password'><button>Go</button></form></body></html>",
    "/wp-login.php": b"<html><body><h2>WordPress Login</h2><form method='POST'><input name='log' placeholder='Username'><input name='pwd' type='password' placeholder='Password'><button>Log In</button></form></body></html>",
    "/admin": _HTTP_LOGIN_PAGE,
    "/administrator": _HTTP_LOGIN_PAGE,
    "/manager/html": b"<html><body><h2>Tomcat Manager</h2><form method='POST'><input name='j_username' placeholder='Username'><input name='j_password' type='password' placeholder='Password'><button>Login</button></form></body></html>",
}


class _HTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default logging

    def _get_client_ip(self):
        return self.client_address[0]

    def do_GET(self):
        ip = self._get_client_ip()
        parsed = urlparse(self.path)
        headers_str = str(dict(self.headers))
        log_event("http", ip, source_port=self.client_address[1], dest_port=Config.HTTP_PORT,
                  event_type="http_get", payload=f"GET {self.path} headers={headers_str[:200]}")

        body = _FAKE_PAGES.get(parsed.path, _HTTP_LOGIN_PAGE)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", Config.HTTP_SERVER)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        ip = self._get_client_ip()
        length  = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(length).decode(errors="replace") if length else ""
        parsed  = parse_qs(payload)

        # Extract credentials from common field names
        user = next((parsed[k][0] for k in ("user", "username", "log", "j_username", "pma_username") if k in parsed), None)
        pwd  = next((parsed[k][0] for k in ("pass", "password", "pwd", "j_password", "pma_password") if k in parsed), None)

        log_event("http", ip, source_port=self.client_address[1], dest_port=Config.HTTP_PORT,
                  event_type="http_post_creds", username=user, password=pwd,
                  payload=f"POST {self.path} body={payload[:300]}")

        self.send_response(401)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", Config.HTTP_SERVER)
        self.send_header("Content-Length", str(len(_HTTP_DENIED)))
        self.end_headers()
        self.wfile.write(_HTTP_DENIED)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Server", Config.HTTP_SERVER)
        self.end_headers()


class HTTPHoneypot(BaseHoneypot):
    service_name = "http"

    def _listen(self):
        class _Server(HTTPServer):
            timeout = 1

        srv = _Server(("0.0.0.0", self.port), _HTTPHandler)
        while not self._stop.is_set():
            srv.handle_request()
        srv.server_close()


# ── Telnet Honeypot ───────────────────────────────────────────────────────────

TELNET_IAC  = bytes([255])
TELNET_WILL = bytes([251])
TELNET_DO   = bytes([253])
TELNET_ECHO = bytes([1])
TELNET_SGA  = bytes([3])


def _handle_telnet_client(client_sock: socket.socket, addr: tuple):
    ip, port = addr
    session_id = uuid.uuid4().hex[:12]
    log_event("telnet", ip, source_port=port, dest_port=Config.TELNET_PORT,
              event_type="connection", session_id=session_id)

    try:
        client_sock.settimeout(30)
        # Negotiate: WILL ECHO, WILL SGA
        client_sock.sendall(TELNET_IAC + TELNET_WILL + TELNET_ECHO +
                            TELNET_IAC + TELNET_WILL + TELNET_SGA)

        def read_line():
            buf = b""
            while True:
                b = BaseHoneypot._safe_recv(client_sock, 1)
                if not b:
                    return None
                if b[0] == 255:  # IAC
                    BaseHoneypot._safe_recv(client_sock, 2)
                    continue
                if b in (b"\r", b"\n"):
                    return buf.decode(errors="replace").strip()
                buf += b

        client_sock.sendall(b"\r\nUbuntu 20.04.6 LTS\r\n")
        client_sock.sendall(b"ip-172-31-14-22 login: ")
        username = read_line()

        client_sock.sendall(b"Password: ")
        password = read_line()

        log_event("telnet", ip, source_port=port, dest_port=Config.TELNET_PORT,
                  event_type="auth_attempt", username=username, password=password,
                  session_id=session_id)

        client_sock.sendall(b"\r\nLogin incorrect\r\n")

        # Try again
        client_sock.sendall(b"ip-172-31-14-22 login: ")
        username2 = read_line()
        client_sock.sendall(b"Password: ")
        password2 = read_line()

        if username2 and password2:
            log_event("telnet", ip, source_port=port, dest_port=Config.TELNET_PORT,
                      event_type="auth_attempt", username=username2, password=password2,
                      session_id=session_id)

        client_sock.sendall(b"\r\nLogin incorrect\r\n\r\n")

    except Exception as exc:
        logger.debug("Telnet session error %s: %s", ip, exc)
    finally:
        client_sock.close()


class TelnetHoneypot(BaseHoneypot):
    service_name = "telnet"

    def _listen(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(50)
        srv.settimeout(1)

        while not self._stop.is_set():
            try:
                client_sock, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            ip = addr[0]
            if is_banned(ip) or not _rate_limiter.allow(ip):
                client_sock.close()
                continue

            threading.Thread(target=_handle_telnet_client,
                             args=(client_sock, addr), daemon=True).start()
        srv.close()


# ── MySQL Honeypot ────────────────────────────────────────────────────────────

def _make_mysql_greeting() -> bytes:
    version    = Config.MYSQL_VERSION.encode() + b"\x00"
    conn_id    = struct.pack("<I", 1)
    auth_p1    = b"^CUe~S9V\x00"          # 8 bytes + null
    caps1      = struct.pack("<H", 0xF7FF)
    charset    = bytes([33])
    status     = struct.pack("<H", 0x0002)
    caps2      = struct.pack("<H", 0x01FF)
    auth_len   = bytes([21])
    reserved   = b"\x00" * 10
    auth_p2    = b"3?J]?LW@0\x00\x00\x00"
    auth_name  = b"mysql_native_password\x00"

    payload = (bytes([10]) + version + conn_id + auth_p1 +
               caps1 + charset + status + caps2 +
               auth_len + reserved + auth_p2 + auth_name)
    pkt_len = struct.pack("<I", len(payload))[:3]
    return pkt_len + b"\x00" + payload


def _handle_mysql_client(client_sock: socket.socket, addr: tuple):
    ip, port = addr
    session_id = uuid.uuid4().hex[:12]
    log_event("mysql", ip, source_port=port, dest_port=Config.MYSQL_PORT,
              event_type="connection", session_id=session_id)

    try:
        client_sock.settimeout(15)
        client_sock.sendall(_make_mysql_greeting())

        # Read client auth packet
        raw = BaseHoneypot._safe_recv(client_sock, 4096)
        if raw and len(raw) > 36:
            # Parse username from MySQL client auth packet (offset ~36)
            try:
                null_idx = raw.index(b"\x00", 36)
                username = raw[36:null_idx].decode(errors="replace")
            except (ValueError, UnicodeDecodeError):
                username = None

            log_event("mysql", ip, source_port=port, dest_port=Config.MYSQL_PORT,
                      event_type="auth_attempt", username=username,
                      payload=raw[:80].hex(), session_id=session_id)

        # Send access denied
        err = b"\xff\x15\x04#28000Access denied for user 'root'@'any' (using password: YES)"
        pkt_len = struct.pack("<I", len(err))[:3]
        client_sock.sendall(pkt_len + b"\x02" + err)

    except Exception as exc:
        logger.debug("MySQL session error %s: %s", ip, exc)
    finally:
        client_sock.close()


class MySQLHoneypot(BaseHoneypot):
    service_name = "mysql"

    def _listen(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(50)
        srv.settimeout(1)

        while not self._stop.is_set():
            try:
                client_sock, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            ip = addr[0]
            if is_banned(ip) or not _rate_limiter.allow(ip):
                client_sock.close()
                continue

            threading.Thread(target=_handle_mysql_client,
                             args=(client_sock, addr), daemon=True).start()
        srv.close()


# ── Redis Honeypot ────────────────────────────────────────────────────────────

def _handle_redis_client(client_sock: socket.socket, addr: tuple):
    ip, port = addr
    session_id = uuid.uuid4().hex[:12]
    log_event("redis", ip, source_port=port, dest_port=Config.REDIS_PORT,
              event_type="connection", session_id=session_id)

    try:
        client_sock.settimeout(30)
        # Send Redis inline banner
        client_sock.sendall(b"+OK\r\n")

        buf = b""
        while True:
            data = BaseHoneypot._safe_recv(client_sock, 4096)
            if not data:
                break
            buf += data
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                cmd_text = line.decode(errors="replace").strip()
                if not cmd_text or cmd_text.startswith("*") or cmd_text.startswith("$"):
                    continue

                log_event("redis", ip, source_port=port, dest_port=Config.REDIS_PORT,
                          event_type="command", payload=cmd_text[:500], session_id=session_id)

                upper = cmd_text.upper()
                if upper.startswith("PING"):
                    client_sock.sendall(b"+PONG\r\n")
                elif upper.startswith("INFO"):
                    info = b"$120\r\n# Server\r\nredis_version:6.2.7\r\nredis_mode:standalone\r\nos:Linux 5.15.0 x86_64\r\narch_bits:64\r\nuptime_in_seconds:86400\r\n\r\n"
                    client_sock.sendall(info)
                elif upper.startswith("CONFIG"):
                    client_sock.sendall(b"-ERR CONFIG disabled\r\n")
                elif upper.startswith("KEYS"):
                    client_sock.sendall(b"*0\r\n")
                elif upper.startswith("AUTH"):
                    client_sock.sendall(b"-ERR invalid password\r\n")
                elif upper.startswith("QUIT"):
                    client_sock.sendall(b"+OK\r\n")
                    break
                else:
                    client_sock.sendall(b"-ERR unknown command\r\n")

    except Exception as exc:
        logger.debug("Redis session error %s: %s", ip, exc)
    finally:
        client_sock.close()


class RedisHoneypot(BaseHoneypot):
    service_name = "redis"

    def _listen(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(50)
        srv.settimeout(1)

        while not self._stop.is_set():
            try:
                client_sock, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            ip = addr[0]
            if is_banned(ip) or not _rate_limiter.allow(ip):
                client_sock.close()
                continue

            threading.Thread(target=_handle_redis_client,
                             args=(client_sock, addr), daemon=True).start()
        srv.close()


# ── SMTP Honeypot ─────────────────────────────────────────────────────────────

def _handle_smtp_client(client_sock: socket.socket, addr: tuple):
    ip, port = addr
    session_id = uuid.uuid4().hex[:12]
    log_event("smtp", ip, source_port=port, dest_port=Config.SMTP_PORT,
              event_type="connection", session_id=session_id)

    try:
        client_sock.settimeout(30)
        client_sock.sendall(b"220 mail.ubuntu-server.local ESMTP Postfix\r\n")

        def read_line():
            buf = b""
            while True:
                b = BaseHoneypot._safe_recv(client_sock, 1)
                if not b or b in (b"\n",):
                    break
                if b != b"\r":
                    buf += b
            return buf.decode(errors="replace").strip()

        mail_from = rcpt_to = None
        while True:
            line = read_line()
            if not line:
                break

            upper = line.upper()
            log_event("smtp", ip, source_port=port, dest_port=Config.SMTP_PORT,
                      event_type="smtp_command", payload=line[:300], session_id=session_id)

            if upper.startswith("EHLO") or upper.startswith("HELO"):
                client_sock.sendall(b"250-mail.ubuntu-server.local Hello\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n")
            elif upper.startswith("AUTH"):
                client_sock.sendall(b"535 5.7.8 Authentication failed\r\n")
            elif upper.startswith("MAIL FROM"):
                mail_from = line
                client_sock.sendall(b"250 OK\r\n")
            elif upper.startswith("RCPT TO"):
                rcpt_to = line
                client_sock.sendall(b"250 OK\r\n")
            elif upper == "DATA":
                client_sock.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                data_buf = []
                while True:
                    dline = read_line()
                    if dline == ".":
                        break
                    data_buf.append(dline)
                log_event("smtp", ip, source_port=port, dest_port=Config.SMTP_PORT,
                          event_type="smtp_data",
                          payload=f"FROM={mail_from} TO={rcpt_to} DATA={' '.join(data_buf)[:300]}",
                          session_id=session_id)
                client_sock.sendall(b"250 OK: Message accepted\r\n")
            elif upper == "QUIT":
                client_sock.sendall(b"221 Bye\r\n")
                break
            else:
                client_sock.sendall(b"502 Command not implemented\r\n")

    except Exception as exc:
        logger.debug("SMTP session error %s: %s", ip, exc)
    finally:
        client_sock.close()


class SMTPHoneypot(BaseHoneypot):
    service_name = "smtp"

    def _listen(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port))
        srv.listen(50)
        srv.settimeout(1)

        while not self._stop.is_set():
            try:
                client_sock, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            ip = addr[0]
            if is_banned(ip) or not _rate_limiter.allow(ip):
                client_sock.close()
                continue

            threading.Thread(target=_handle_smtp_client,
                             args=(client_sock, addr), daemon=True).start()
        srv.close()


# ── Manager ───────────────────────────────────────────────────────────────────

class HoneypotManager:
    def __init__(self):
        self.services = [
            SSHHoneypot(Config.SSH_PORT),
            FTPHoneypot(Config.FTP_PORT),
            HTTPHoneypot(Config.HTTP_PORT),
            TelnetHoneypot(Config.TELNET_PORT),
            MySQLHoneypot(Config.MYSQL_PORT),
            RedisHoneypot(Config.REDIS_PORT),
            SMTPHoneypot(Config.SMTP_PORT),
        ]
        self._running = False

    def start(self):
        init_db()
        self._running = True
        for svc in self.services:
            try:
                svc.start()
            except Exception as exc:
                logger.error("Failed to start %s: %s", svc.service_name, exc)
        logger.info("All honeypot services started.")

    def stop(self):
        self._running = False
        for svc in self.services:
            svc.stop()
        logger.info("All honeypot services stopped.")

    def status(self) -> list:
        return [
            {
                "service": svc.service_name,
                "port":    svc.port,
                "running": svc._thread is not None and svc._thread.is_alive(),
            }
            for svc in self.services
        ]
