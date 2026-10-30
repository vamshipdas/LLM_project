import os
import smtplib
import ssl
import socket
from pathlib import Path
from dotenv import load_dotenv

# Load backend/.env
env_path = Path(__file__).resolve().parent.parent / "backend" / ".env"
load_dotenv(dotenv_path=env_path)

host = os.getenv("SMTP_HOST", "smtp.gmail.com")
port = int(os.getenv("SMTP_PORT", 587))
user = os.getenv("SMTP_USER", "")
password = os.getenv("SMTP_PASSWORD", "")

# Remove spaces if user copied it with spaces (e.g. "abcd efgh ijkl mnop")
if password:
    password = password.strip().replace(" ", "")

if not user or not password:
    print("missing credentials in .env")
    exit(1)

try:
    server = smtplib.SMTP(host=host, port=port, timeout=15)
    server.ehlo()
    context = ssl.create_default_context()
    server.starttls(context=context)
    server.ehlo()
    server.login(user, password)
    server.quit()
    print("OK")
except smtplib.SMTPAuthenticationError as e:
    # 535 authentication failed
    code = getattr(e, "smtp_code", None)
    if code == 535 or "535" in str(e):
        print("auth 535")
    else:
        print(f"auth error: {code}")
except ssl.SSLError:
    print("TLS")
except (socket.timeout, TimeoutError):
    print("timeout")
except (socket.gaierror, ConnectionRefusedError, OSError):
    print("network")
except Exception as e:
    print(f"error: {type(e).__name__}")
