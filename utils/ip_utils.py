import requests
import json
import time
import socket
import ipaddress
import threading
from config import CONFIG, geo_cache, geo_cache_lock, geo_queue, dns_cache, dns_lock, dns_queue
from utils.logger import log, rolling_logs

def classify_internal_external(ip_str: str):
    if not ip_str or ip_str in ["*", "0.0.0.0", "::"]:
        return "unknown"
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "internal"
        else:
            return "external"
    except Exception:
        return "external"

def get_ip_details(ip: str):
    with geo_cache_lock:
        if ip in geo_cache:
            cached = geo_cache[ip]
            if time.time() - cached["timestamp"] < CONFIG["geo_cache_expiry"]:
                rolling_logs['ipdetails'].info(f"IP: {ip} - Cached: {cached['data']}")
                return cached["data"]
            else:
                del geo_cache[ip]
    
    details = {
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "org": "Unknown",
        "asn": "Unknown",
        "reverse": "Unknown",
        "threat": "Unknown",
        "location": "Unknown",
        "service": "Unknown",
        "api_source": "None",
        "threat_api_source": "None",
        "abuse_score": 0,
        "vt_positives": 0,
        "threat_details": "N/A",
        "vt_stats": {}
    }
    
    if not ip or ip in ["0.0.0.0", "::", "*", ""]:
        return details
    
    rolling_logs['ipdetails'].info(f"IP: {ip} - Starting lookup")
    
    try:
        url = CONFIG["ipinfo_api"].format(ip)
        response = requests.get(url, timeout=CONFIG["geo_timeout"])
        if response.status_code == 200:
            data = response.json()
            details.update({
                "country": data.get("country", "Unknown"),
                "region": data.get("region", "Unknown"),
                "city": data.get("city", "Unknown"),
                "org": data.get("org", "Unknown"),
                "reverse": data.get("hostname", "Unknown"),
                "location": data.get("loc", "Unknown"),
                "api_source": "ipinfo.io"
            })
            rolling_logs['ipdetails'].info(f"IP: {ip} - ipinfo.io result: {details}")
    except (requests.RequestException, json.JSONDecodeError) as e:
        log("WARNING", f"ipinfo.io failed for {ip}: {str(e)}")
    
    if details["org"] == "Unknown":
        try:
            url = CONFIG["ipapi_api"].format(ip)
            response = requests.get(url, timeout=CONFIG["geo_timeout"])
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    details.update({
                        "country": data.get("country", details["country"]),
                        "region": data.get("regionName", details["region"]),
                        "city": data.get("city", details["city"]),
                        "org": data.get("org", data.get("isp", details["org"])),
                        "asn": data.get("as", details["asn"]),
                        "reverse": data.get("reverse", details["reverse"]),
                        "api_source": "ip-api.com"
                    })
                    if 'lat' in data and 'lon' in data:
                        details['location'] = f"{data['lat']},{data['lon']}"
                    rolling_logs['ipdetails'].info(f"IP: {ip} - ip-api.com result: {details}")
        except (requests.RequestException, json.JSONDecodeError) as e:
            log("WARNING", f"ip-api.com failed for {ip}: {str(e)}")
    
    if details["asn"] == "Unknown" or details["org"] == "Unknown":
        try:
            url = CONFIG["rdap_api"].format(ip)
            response = requests.get(url, timeout=CONFIG["geo_timeout"])
            if response.status_code == 200:
                data = response.json()
                entities = data.get("entities", [])
                for entity in entities:
                    if "registrant" in entity.get("roles", []):
                        details["org"] = entity.get("vcardArray", [])[1][0][3] or details["org"]
                details["asn"] = data.get("asn", details["asn"])
                details["api_source"] = "RDAP"
                rolling_logs['ipdetails'].info(f"IP: {ip} - RDAP result: {details}")
        except (requests.RequestException, json.JSONDecodeError) as e:
            log("WARNING", f"RDAP failed for {ip}: {str(e)}")
    
    if classify_internal_external(ip) == "external":
        try:
            url = CONFIG["abuseipdb_api"]
            headers = {'Accept': 'application/json', 'Key': CONFIG["abuseipdb_key"]}
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            response = requests.get(url, headers=headers, params=params, timeout=CONFIG["geo_timeout"])
            if response.status_code == 200:
                data = response.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                details['abuse_score'] = score
                if score >= CONFIG["threat_intel"]["abuseipdb_threshold"]:
                    details['threat'] = "High Risk (AbuseIPDB)"
                    details['threat_details'] = f"Score: {score}, Reports: {data.get('totalReports', 0)}"
                    details['threat_api_source'] = "AbuseIPDB"
                rolling_logs['ipdetails'].info(f"IP: {ip} - AbuseIPDB score: {score}")
        except (requests.RequestException, json.JSONDecodeError) as e:
            log("WARNING", f"AbuseIPDB failed for {ip}: {str(e)}")
        try:
            url = CONFIG["virustotal_api"].format(ip)
            headers = {"accept": "application/json", "x-apikey": CONFIG["virustotal_key"]}
            response = requests.get(url, headers=headers, timeout=CONFIG["geo_timeout"])
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                details['vt_stats'] = stats 
                malicious_count = stats.get('malicious', 0)
                details['vt_positives'] = malicious_count
                if malicious_count >= CONFIG["threat_intel"]["vt_malicious_threshold"]:
                    details['threat'] = "Malicious (VirusTotal)"
                    total_scans = stats.get('harmless', 0) + stats.get('suspicious', 0) + malicious_count
                    details['threat_details'] = f"VT Detections: {malicious_count}/{total_scans}"
                    details['threat_api_source'] = "VirusTotal"
                rolling_logs['ipdetails'].info(f"IP: {ip} - VirusTotal malicious count: {malicious_count}")
        except (requests.RequestException, json.JSONDecodeError) as e:
            log("WARNING", f"VirusTotal failed for {ip}: {str(e)}")
    port = ""
    if ":" in ip:
        ip, port = ip.split(":", 1)
    port = int(port) if port.isdigit() else 0
    
    if port == 443 or "https" in details["reverse"]:
        details["service"] = "HTTPS"
    elif port == 80 or "http" in details["reverse"]:
        details["service"] = "HTTP"
    elif port in [21, 22, 23]:
        details["service"] = "FTP/SSH/Telnet"
    elif port in [25, 465, 587]:
        details["service"] = "Email"
    elif port in [53, 853]:
        details["service"] = "DNS"
    else:
        org_lower = details["org"].lower()
        if "cloudflare" in org_lower:
            details["service"] = "CDN"
        elif "amazon" in org_lower or "aws" in org_lower:
            details["service"] = "Cloud Hosting"
        elif "google" in org_lower:
            details["service"] = "Google Services"
        elif "microsoft" in org_lower or "azure" in org_lower:
            details["service"] = "Microsoft Services"
        elif "akamai" in org_lower:
            details["service"] = "CDN"
        elif "cdn" in org_lower:
            details["service"] = "CDN"
        elif "host" in org_lower or "server" in org_lower:
            details["service"] = "Hosting"
        else:
            details["service"] = "Unknown"
    
    with geo_cache_lock:
        if len(geo_cache) > CONFIG["geo_cache_max"]:
            oldest = min(geo_cache.items(), key=lambda x: x[1]["timestamp"])
            del geo_cache[oldest[0]]
        
        geo_cache[ip] = {
            "data": details,
            "timestamp": time.time()
        }
    
    rolling_logs['ipdetails'].info(f"IP: {ip} - Final details: {details}")
    return details

def geo_worker():
    while True:
        item = geo_queue.get()
        if item is None:
            break
        ip, callback = item
        try:
            details = get_ip_details(ip)
            if callback:
                callback(ip, details)
        except Exception as e:
            log("ERROR", f"Geo worker error: {e}")
        finally:
            geo_queue.task_done()

def reverse_dns_worker():
    while True:
        item = dns_queue.get()
        if item is None:
            break
        ip, callback = item
        try:
            if ip in dns_cache:
                callback(dns_cache[ip])
            else:
                try:
                    host = socket.gethostbyaddr(ip)[0]
                except Exception:
                    host = None
                with dns_lock:
                    dns_cache[ip] = host
                callback(host)
        except Exception as e:
            callback(None)
        dns_queue.task_done()