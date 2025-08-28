import logging
from logging.handlers import RotatingFileHandler
import os
import datetime

def setup_logging():
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    main_logger = logging.getLogger('main')
    main_logger.setLevel(logging.INFO)
    main_handler = RotatingFileHandler('logs/network.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    main_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    main_logger.addHandler(main_handler)
    
    log_categories = [
        'live_netstat',
        'security_alerts',
        'general_alerts',
        'connections',
        'metadata',
        'ipdetails',
        'domains',
        'forensics'
    ]
    
    rolling_logs = {}
    
    for category in log_categories:
        logger = logging.getLogger(category)
        logger.setLevel(logging.INFO)
        
        handler = RotatingFileHandler(f'logs/{category}.log', maxBytes=100*1024, backupCount=1, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        logger.addHandler(handler)
        
        rolling_logs[category] = logger
    
    return main_logger, rolling_logs

main_logger, rolling_logs = setup_logging()

def log(level: str, message: str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {message}"
    
    main_logger.info(f"{level} - {message}")
    
    print(line)