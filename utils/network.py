import subprocess
import re
from config import proc_cache, proc_cache_lock
from utils.logger import log, rolling_logs

NETSTAT_RE = re.compile(r'^(?P<proto>\S+)\s+(?P<local>\S+)\s+(?P<remote>\S+)\s+(?P<state>\S+)\s*(?P<pid>\d+)?',
                        re.IGNORECASE)


def run_netstat_windows():
    try:
        # Add creationflags to prevent the console window from flashing
        proc = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        out = proc.stdout or proc.stderr or ""
        lines = out.splitlines()

        rolling_logs['live_netstat'].info("Live Netstat Output:\n" + "\n".join(lines))

        return lines
    except Exception as e:
        log("ERROR", f"netstat command failed: {e}")
        return []


def split_addr_port(token: str):
    if token == '*:*' or token == '0.0.0.0:0':
        return "*", None

    if token.startswith('[') and ']' in token:
        ip = token[1:token.index(']')]
        rest = token[token.index(']') + 1:]
        port = None
        if rest.startswith(':'):
            try:
                port = int(rest[1:])
            except:
                port = None
        return ip, port
    if ':' in token:
        try:
            ip_part, port_part = token.rsplit(':', 1)
            return ip_part, int(port_part) if port_part.isdigit() else (ip_part, None)
        except Exception:
            return token, None
    return token, None


def pid_to_proc(pid: int):
    if not pid:
        return None
    with proc_cache_lock:
        if pid in proc_cache:
            return proc_cache[pid]
    name = None
    try:
        # Add creationflags here as well
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        out = result.stdout
        for line in out.splitlines():
            if str(pid) in line:
                parts = line.split()
                if parts:
                    name = parts[0]
                    break
    except Exception:
        name = None
    with proc_cache_lock:
        proc_cache[pid] = name
    return name


def parse_netstat_lines(lines):
    for line in lines:
        try:
            line = line.strip()
            if not line:
                continue
            if not (line.startswith("TCP") or line.startswith("UDP") or line.startswith("tcp") or line.startswith(
                    "udp")):
                continue
            parts = re.split(r'\s+', line)
            proto = parts[0]
            pid = None
            for tok in reversed(parts):
                if tok.isdigit():
                    pid = int(tok)
                    break
            local_tok, remote_tok, state_tok = None, None, None
            if len(parts) >= 4:
                local_tok = parts[1]
                remote_tok = parts[2]
                if len(parts) >= 5:
                    state_tok = parts[3]
            if not local_tok or not remote_tok:
                ipport_tokens = [p for p in parts if ':' in p or p.startswith('[')]
                if len(ipport_tokens) >= 2:
                    local_tok = ipport_tokens[0]
                    remote_tok = ipport_tokens[1]
            if not local_tok or not remote_tok:
                continue
            local_ip, local_port = split_addr_port(local_tok)
            remote_ip, remote_port = split_addr_port(remote_tok)
            state_m = re.search(r'\b(ESTABLISHED|LISTENING|LISTEN|TIME_WAIT|CLOSE_WAIT|SYN_SENT|SYN_RECV|LAST_ACK)\b',
                                line, re.IGNORECASE)
            state = state_m.group(1) if state_m else (state_tok or "")
            procname = pid_to_proc(pid) if pid else None
            rec = {
                "proto": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state,
                "pid": pid,
                "process": procname,
                "line_raw": line
            }
            yield rec
        except Exception as e:
            log("ERROR", f"Error parsing line: {line} -> {e}")