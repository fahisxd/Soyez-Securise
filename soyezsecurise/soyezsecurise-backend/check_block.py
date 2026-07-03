import redis
import os
import time
import psycopg2
import traceback
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from logger import (
    login_logger,
    db_logger,
    sys_logger,
    otp_logger,
    Log_event
)
load_dotenv()
ip_db = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

DATABASE_URL = os.getenv("DATABASE_URL")
def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


conn = get_db_connection()
cursor = conn.cursor()

def blocker(ip, request_id):
    try:
        if ip_db.exists(f"sus:{ip}"):
            ip_db.incr(f"sus:{ip}")
        else:
            ip_db.set(f"sus:{ip}", 1)
            ip_db.expire(f"sus:{ip}", 3600)

        susscore = int(ip_db.get(f"sus:{ip}"))

        if susscore >= 20:
            cursor.execute("SELECT times_blocked FROM sususers WHERE ip = %s;", (ip,))
            row = cursor.fetchone()

            if not row:
                cursor.execute("INSERT INTO sususers(ip, times_blocked) VALUES(%s, 1);", (ip,))
                times_blocked = 1
            else:
                times_blocked = row['times_blocked']

            expires = int(time.time()) + (3600 * times_blocked)

            # Update times_blocked
            cursor.execute("UPDATE sususers SET times_blocked = times_blocked + 1 WHERE ip = %s;", (ip,))

            # Check if already blocked
            cursor.execute("SELECT * FROM blocked WHERE ip = %s;", (ip,))
            already_blocked = cursor.fetchone()

            if not already_blocked:
                cursor.execute(
                    "INSERT INTO blocked(ip, blocked, time) VALUES(%s, 'yes', %s);",
                    (ip, expires)
                )

            conn.commit()

            Log_event(
                sys_logger,
                "/check_block.py",
                "CRITICAL",
                "IP Blocked",
                "--",
                f"{ip}",
                f"{request_id}"
            )

            return "IP BLOCKED"

    except Exception as e:
        Log_event(
            sys_logger,
            "/check_block.py:blocker",
            "ERROR",
            traceback.format_exc(),
            "--",
            f"{ip}",
            f"{request_id}"
        )
        conn.rollback()

    return "not blocked"


def check(ip):
    try:
        now = int(time.time())
        cursor.execute("SELECT time FROM blocked WHERE ip = %s;", (ip,))
        row = cursor.fetchone()

        if row:
            if now > row['time']:
                cursor.execute("DELETE FROM blocked WHERE ip = %s;", (ip,))
                conn.commit()
                return "not blocked"
            else:
                return "IP BLOCKED"
        else:
            return "not blocked"

    except Exception:
        Log_event(
            sys_logger,
            "/check_block.py:check",
            "ERROR",
            traceback.format_exc(),
            "--",
            f"{ip}",
            "-"
        )
        return "not blocked"
