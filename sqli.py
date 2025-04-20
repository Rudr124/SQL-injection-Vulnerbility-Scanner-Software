from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO
import asyncio
import aiohttp
import csv
import re
import random
import urllib.parse
import time
import os
from threading import Event, Thread

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')

stop_event = Event()
scan_results = []  # Store scan results globally

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
    "Mozilla/5.0 (X11; Linux x86_64)..."
]

SQL_ERROR_PATTERNS = re.compile(
    r"(" + r"|".join([
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlClient\\.",
        r"check the manual that corresponds to your MySQL",
        r"SQLSTATE\\[HY000\\]", r"supplied argument is not a valid MySQL",
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Syntax error in string in query expression",
        r"java\\.sql\\.SQLException", r"org\\.hibernate\\.QueryException",
        r"com\\.mysql\\.jdbc\\.exceptions", r"PostgreSQL.*ERROR",
        r"pg_query\\(\\): Query failed:", r"System\\.Data\\.OleDb\\.OleDbException",
        r"SQLite/JDBCDriver", r"SQLITE_ERROR", r"Unterminated string literal",
        r"quoted string not properly terminated", r"truncated incorrect",
        r"Data truncation", r"illegal mix of collations",
        r"parameter index out of range", r"ORA-00933: SQL command not properly ended",
        r"ORA-00936: missing expression", r"ORA-01756: quoted string not properly terminated",
        r"DB2 SQL error:", r"Informix ODBC Driver", r"Dynamic SQL Error",
        r"Invalid SQL statement", r"incorrect syntax near",
        r"unexpected end of SQL command", r"unterminated quoted string",
        r"fatal error in database engine", r"Invalid Querystring",
        r"ADODB.Field error", r"XPATH syntax error",
        r"You have an error in your SQL syntax", r"Invalid URI",
        r"Unknown column", r"invalid number format", r"SQL logic error",
        r"Unable to fetch row", r"ORA-00921: unexpected end of SQL command",
        r"SQL Server Native Client error", r"Invalid column reference",
        r"Jet database engine error", r"Error Executing Database Query",
        r"Invalid SQL data type", r"missing right parenthesis",
        r"Invalid table alias", r"conversion failed when converting",
        r"subquery returned more than 1 value", r"Ambiguous column name",
        r"Unrecognized token", r"cannot commit transaction"
    ]) + r")", re.IGNORECASE
)

def detect_sql_error(response_text):
    return bool(SQL_ERROR_PATTERNS.search(response_text))

async def send_request(session, base_url, param, payload):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    url = f"{base_url.rstrip('/')}?{param}={urllib.parse.quote(payload)}"
    try:
        start_time = time.time()
        async with session.get(url, headers=headers, timeout=2) as response:
            duration = round(time.time() - start_time, 2)
            text = await response.text()
            vulnerable = detect_sql_error(text) or duration > 1.5
            result = {
                "url": url,
                "status": response.status,
                "time": duration,
                "payload": payload,
                "vulnerable": vulnerable
            }
            scan_results.append(result)  # Store result
            socketio.emit("scan_update", result)
    except:
        pass

async def limited_request(session, base_url, param, payload, semaphore):
    async with semaphore:
        return await send_request(session, base_url, param, payload)

async def scan_url(target_url, csv_file):
    global scan_results
    scan_results = []  # Clear previous results
    stop_event.clear()

    if not os.path.exists(csv_file):
        socketio.emit("scan_update", {"url": "ERROR", "payload": csv_file, "status": "File not found", "time": 0, "vulnerable": False})
        return

    with open(csv_file, "r") as f:
        reader = csv.reader(f)
        test_cases = [(row[0], row[1]) for row in reader if len(row) >= 2]

    semaphore = asyncio.Semaphore(2000)
    connector = aiohttp.TCPConnector(limit_per_host=100)
    async with aiohttp.ClientSession(connector=connector) as session:
        for p, v in test_cases:
            if stop_event.is_set():
                socketio.emit("scan_update", {"url": "STOPPED", "payload": "", "status": "Scan stopped", "time": 0, "vulnerable": False})
                return
            await limited_request(session, target_url, p, v, semaphore)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start_scan", methods=["POST"])
def start_scan():
    target_url = request.form.get("target_url")
    csv_file = request.form.get("csv_file")

    if not target_url or not csv_file:
        return jsonify({"error": "Missing target_url or csv_file"}), 400

    def run_background():
        asyncio.run(scan_url(target_url, csv_file))

    Thread(target=run_background).start()

    return jsonify({"message": "Scan started"})

@app.route("/stop_scan", methods=["POST"])
def stop_scan():
    stop_event.set()
    return jsonify({"message": "Scan stopped by user."})

@app.route("/download_report")
def download_report():
    report_file = "scan_report.csv"
    with open(report_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Status", "Time", "Payload", "Vulnerable"])
        for r in scan_results:
            writer.writerow([r["url"], r["status"], r["time"], r["payload"], r["vulnerable"]])
    return send_file(report_file, as_attachment=True)

if __name__ == "__main__":
    socketio.run(app, debug=True)
