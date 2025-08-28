import time
from config import alert_lock, alert_history

def should_alert(alert_type: str, key: str, cooldown_seconds: int) -> bool:
    now = time.time()
    with alert_lock:
        if key in alert_history[alert_type]:
            last_alert = alert_history[alert_type][key]
            if now - last_alert < cooldown_seconds:
                return False
        alert_history[alert_type][key] = now
        return True

def determine_alert_severity(alert_type: str, level: str):
    security_types = ["DDOS", "SMB", "IPv6_RA"]
    security_levels = ["CRITICAL", "HIGH"]
    
    if alert_type in security_types or level in security_levels:
        return "security"
    
    if alert_type == "SUSPICIOUS":
        return "general"
    
    return "general"