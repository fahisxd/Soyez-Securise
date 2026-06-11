import redis
import sqlite3
import time
import os
from logger import (
    login_logger,
    db_logger,
    sys_logger,
    otp_logger,
    Log_event
)
DATABASE_URL = os.getenv("POSTGRES_URL")
REDIS_URL = os.getenv("REDIS_DB")

ip_db = redis.Redis.from_url(REDIS_URL,decode_responses=True)
conn = psycopg2.connect(
    DATABASE_URL,
    cursor_factory=RealDictCursor
)
cursor = conn.cursor()

def blocker(ip, request_id):

    if ip_db.exists(f"sus:{ip}"):

        ip_db.incr(f"sus:{ip}")

    else:

        ip_db.set(f"sus:{ip}", 1)
        ip_db.expire(f"sus:{ip}", 3600)


    susscore = int(ip_db.get(f"sus:{ip}"))

    if susscore >= 20:

        cursor.execute(
"""
SELECT times_blocked
FROM sususers
WHERE ip = ?;
""",
(ip,)
)

        row = cursor.fetchone()

        if not row:

            cursor.execute(
"""
INSERT INTO sususers(ip, times_blocked)
VALUES(?,1)
""",
(ip,)
)

            times_blocked = 1

        else:

            times_blocked = row[0]


        expires = int(time.time()) + (3600 * times_blocked)

        cursor.execute(
"""
UPDATE sususers
SET times_blocked = times_blocked + 1
WHERE ip = ?;
""",
(ip,)
)
        cursor.execute(
        """
        SELECT * FROM blocked
        WHERE ip = ?;
        """,
        (ip,)
        )

        already_blocked = cursor.fetchone()

        if already_blocked:
            return "IP BLOCKED"
        else:
            cursor.execute(
            """
            INSERT INTO blocked(ip, blocked, time)
            VALUES(?,?,?)
            """,
            (ip, "yes", expires)
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


def check(ip):
    now = int(time.time())
    cursor.execute("""
        SELECT time FROM blocked WHERE ip = ?;
        """, (ip,))
    row = cursor.fetchone()
    if row:
        if now > row[0]:
            cursor.execute(
            """
            DELETE FROM blocked
            WHERE ip = ?
            """,
            (ip,)
            )

            conn.commit()
        else:
            return "IP BLOCKED"
    else:
        return "not blocked"



    
