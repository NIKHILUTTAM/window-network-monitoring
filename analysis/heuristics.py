import time
import queue
from config import CONFIG, conn_timestamps, smb_counts, ipv6_counts, alerts_q, dns_queue
from utils.logger import log, rolling_logs
from utils.ip_utils import classify_internal_external
from analysis.alerting import should_alert

def normalize_ipv6_interface(ip_str):
    if ip_str and ip_str.startswith('fe80:'):
        if '%' in ip_str:
            return ip_str.split('%')[0]
    return ip_str

def mark_suspicious_by_ip_or_host(ip_or_host: str):
    if not ip_or_host:
        return None
    s = ip_or_host.lower()
    for p in CONFIG["suspicious"]["malicious_ip_prefixes"]:
        if s.startswith(p):
            return "malicious"
    for tok in CONFIG["suspicious"]["social_media_domains"]:
        if tok in s:
            return "social_media"
    for tok in CONFIG["suspicious"]["ecommerce_domains"]:
        if tok in s:
            return "ecommerce"
    return None

def feed_record(record):
    now = time.time()
    rip = record.get("remote_ip")
    lip = record.get("local_ip")
    pid = record.get("pid") or 0
    state = record.get("state","")
    procname = record.get("process")

    rolling_logs['connections'].info(
        f"Connection: {record.get('proto')} {record.get('local_ip')}:{record.get('local_port')} -> "
        f"{rip}:{record.get('remote_port')} State: {state} PID: {pid} Process: {procname}"
    )
    try:
        window = CONFIG["ddos"]["window_seconds"]
        dq = conn_timestamps[rip]
        dq.append(now)
        while dq and dq[0] < now - window:
            dq.popleft()
        rate = len(dq) / max(1.0, window)
        if rate > CONFIG["ddos"]["threshold_conn_per_sec"]:
            if should_alert("ddos", rip, CONFIG["ddos"]["alert_cooldown"]):
                msg = f"Possible DDoS: {rip} receiving connections at {rate:.1f}/s (threshold {CONFIG['ddos']['threshold_conn_per_sec']})"
                alert = {"type":"DDOS", "level":"CRITICAL", "message":msg, "evidence": record}
                log("CRITICAL", msg + f" evidence: {record.get('line_raw')}")
                alerts_q.put(alert)
    except Exception as e:
        log("ERROR", f"DDoS detection error: {e}")

    try:
        if record.get("remote_port") in (445, 139):
            classification = classify_internal_external(rip)
            if classification == "external":
                key = (lip, pid)
                smb_counts[key] += 1
                if smb_counts[key] >= CONFIG["smb"]["external_conn_threshold"]:
                    alert_key = f"{lip}:{pid}"
                    if should_alert("smb", alert_key, CONFIG["smb"]["alert_cooldown"]):
                        msg = f"Suspicious SMB activity: {lip} PID={pid} ({procname}) connected to external SMB {rip} {smb_counts[key]} times"
                        alert = {"type":"SMB", "level":"HIGH", "message":msg, "evidence": record}
                        log("HIGH", msg + f" evidence: {record.get('line_raw')}")
                        alerts_q.put(alert)
    except Exception as e:
        log("ERROR", f"SMB detection error: {e}")

    try:
        if rip and ':' in rip:
            if rip.startswith("fe80"):
                dq6 = ipv6_counts[lip]
                dq6.append(now)
                while dq6 and dq6[0] < now - CONFIG["ipv6"]["window_seconds"]:
                    dq6.popleft()
                if len(dq6) > CONFIG["ipv6"]["ra_count_threshold"]:
                    normalized_lip = normalize_ipv6_interface(lip)
                    if should_alert("ipv6_ra", normalized_lip, CONFIG["ipv6"]["alert_cooldown"]):
                        msg = f"IPv6 RA flood heuristic: {lip} saw {len(dq6)} link-local IPv6 entries in window"
                        alert = {"type":"IPv6_RA", "level":"HIGH", "message":msg, "evidence": record}
                        log("HIGH", msg + f" evidence: {record.get('line_raw')}")
                        alerts_q.put(alert)
    except Exception as e:
        log("ERROR", f"IPv6 detection error: {e}")

    try:
        tag = mark_suspicious_by_ip_or_host(rip)
        if tag:
            if should_alert("suspicious", rip, CONFIG["suspicious"]["alert_cooldown"]):
                msg = f"Suspicious target ({tag}) detected: {rip} from PID={pid} proc={procname}"
                alert = {
                    "type":"SUSPICIOUS",
                    "level":"SUSPICIOUS",
                    "message":msg,
                    "evidence": record,
                    "subtype": tag
                }
                log("SUSPICIOUS", msg + f" evidence: {record.get('line_raw')}")
                alerts_q.put(alert)
        else:
            def dns_callback(hostname):
                if hostname:
                    tag2 = mark_suspicious_by_ip_or_host(hostname)
                    if tag2:
                        alert_key = f"{rip}:{hostname}"
                        if should_alert("suspicious", alert_key, CONFIG["suspicious"]["alert_cooldown"]):
                            msg = f"Suspicious target ({tag2}) detected by reverse DNS: {hostname} ({rip}) PID={pid} proc={procname}"
                            alert = {
                                "type":"SUSPICIOUS",
                                "level":"SUSPICIOUS",
                                "message":msg,
                                "evidence": record,
                                "subtype": tag2
                            }
                            log("SUSPICIOUS", msg + f" evidence: {record.get('line_raw')}")
                            alerts_q.put(alert)
            try:
                dns_queue.put_nowait((rip, dns_callback))
            except queue.Full:
                pass
    except Exception as e:
        log("ERROR", f"Suspicious tagging error: {e}")