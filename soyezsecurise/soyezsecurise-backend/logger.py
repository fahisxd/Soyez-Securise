#----------------------------------------------logging system----------------------------------------------#
import logging
import os
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler

# =========================
# setup
# =========================

os.makedirs("logs", exist_ok=True)
# =========================
# login logger
# =========================

login_logger = logging.getLogger("login")
login_logger.setLevel(logging.INFO)
login_handler = RotatingFileHandler("logs/login.log",maxBytes=1000000,backupCount=3)
login_logger.addHandler(login_handler)

# =========================
# database logger
# =========================

db_logger = logging.getLogger("database")
db_logger.setLevel(logging.INFO)
db_handler = RotatingFileHandler("logs/database.log",maxBytes=1000000,backupCount=3)
db_logger.addHandler(db_handler)

# =========================
# system logger
# =========================

sys_logger = logging.getLogger("system")
sys_logger.setLevel(logging.INFO)
sys_handler = RotatingFileHandler("logs/system.log",maxBytes=1000000,backupCount=3)
sys_logger.addHandler(sys_handler)

# =========================
# otp logger
# =========================

otp_logger = logging.getLogger("otp")
otp_logger.setLevel(logging.INFO)
otp_handler = RotatingFileHandler("logs/otp.log",maxBytes=1000000,backupCount=3)
otp_logger.addHandler(otp_handler)


def Log_event(func, location, level, event, user, ip, request_id):
    log = {
        "level" : level.upper(),
        "request-id": request_id,
        "time": str(datetime.now()),
        "event": event,
        "user": user,
        "ip": ip,
        "location": location
        
    }
    level = level.lower()
    getattr(func, level)(json.dumps(log))
    print(json.dumps(log))
    
