import threading
import queue
from collections import defaultdict, deque

CONFIG = {
    "poll_interval_seconds": 3,
    "ddos": {
        "threshold_conn_per_sec": 50,
        "window_seconds": 10,
        "burst_multiplier": 4,
        "alert_cooldown": 60,
    },
    "smb": {
        "external_conn_threshold": 10,
        "alert_cooldown": 300,
    },
    "ipv6": {
        "ra_count_threshold": 5,
        "window_seconds": 10,
        "alert_cooldown": 120,
    },
    "suspicious": {
        "social_media_domains": ["facebook", "googlevideo", "youtube", "twitter", "x.com", "instagram", "tiktok"],
        "ecommerce_domains": ["amazon", "flipkart", "ebay", "paypal"],
        "malicious_ip_prefixes": ["45.33.", "185.199.", "103.152."],
        "alert_cooldown": 180,
    },
    "filters": {
        "exclude_zero_remote": True,
        "show_only_internal": False,
        "show_listening_only": False,
    },
    "ipinfo_api": "https://ipinfo.io/{}/json",
    "ipapi_api": "http://ip-api.com/json/{}",
    "rdap_api": "https://rdap.db.ripe.net/ip/{}",
    "abuseipdb_api": "https://api.abuseipdb.com/api/v2/check",
    "abuseipdb_key": "##paste your api key##",
    "virustotal_api": "https://www.virustotal.com/api/v3/ip_addresses/{}",
    "virustotal_url_lookup_api": "https://www.virustotal.com/api/v3/urls/{}",
    "virustotal_key": "##paste your VT_api key## ",
    "threat_intel": {
        "abuseipdb_threshold": 75,
        "vt_malicious_threshold": 1
    },
    "geo_timeout": 2.0,
    "geo_cache_expiry": 3600,
    "geo_cache_max": 1000,
    "ui": {
        "min_font_size": 8,
        "max_font_size": 16,
        "base_font_size": 10,
        "responsive_threshold": 800,
        "column_min_width": 80,
        "status_bar_height": 25,
    }
}

# Shared Application State
alert_history = {
    "ddos": {},
    "smb": {},
    "ipv6_ra": {},
    "suspicious": {}
}
alert_lock = threading.Lock()

geo_cache = {}
geo_cache_lock = threading.Lock()
geo_queue = queue.Queue(maxsize=100)

dns_cache = {}
dns_lock = threading.Lock()
dns_queue = queue.Queue()

proc_cache = {}
proc_cache_lock = threading.Lock()

conn_timestamps = defaultdict(deque)
smb_counts = defaultdict(int)
ipv6_counts = defaultdict(deque)
alerts_q = queue.Queue()
