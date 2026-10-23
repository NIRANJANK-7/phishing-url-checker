
from flask import Flask, render_template, request
from urllib.parse import urlsplit
import ipaddress
import re

app = Flask(__name__)

KEYWORDS = [
    "login", "verify", "account",
    "update", "password", "secure"
]


def analyze_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        return None, "Please enter a URL."

    if (
        any(ord(c) < 32 or c.isspace() for c in raw_url)
        or "\\" in raw_url
    ):
        return None, "URL contains invalid whitespace or characters."

    url = raw_url

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    try:
        parts = urlsplit(url)
        host = parts.hostname

        if parts.scheme not in ("http", "https") or not host:
            return None, "Invalid URL format."

        # Validate port syntax
        _ = parts.port

        if "%" in host:
            return None, "Invalid hostname."

        host = host.encode("idna").decode("ascii").lower()

        # Reject malformed domain labels
        if (
            len(host) > 253
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not re.fullmatch(r"[a-z0-9-]+", label)
                for label in host.rstrip(".").split(".")
            )
        ):
            return None, "Invalid hostname."

        host = host.rstrip(".")

    except (ValueError, UnicodeError):
        return None, "Invalid URL format."

    checks = []

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    checks.append(("Uses an IP address", is_ip))
    checks.append(("Contains an @ symbol", "@" in parts.netloc))
    checks.append(("Unusually long URL", len(url) > 100))
    checks.append(("Many subdomains", host.count(".") >= 4))
    checks.append(("Hyphen in hostname", "-" in host))
    checks.append((
        "Uses HTTP instead of HTTPS",
        parts.scheme == "http"
    ))
    checks.append((
        "Contains sensitive keywords",
        any(word in url.lower() for word in KEYWORDS)
    ))

    warnings = [name for name, found in checks if found]

    result = {
        "url": url,
        "domain": host,
        "scheme": parts.scheme,
        "checks": checks,
        "warnings": warnings
    }

    return result, None


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    error = None
    entered_url = ""

    if request.method == "POST":
        entered_url = request.form.get("url", "")
        result, error = analyze_url(entered_url)

    return render_template(
        "index.html",
        result=result,
        error=error,
        entered_url=entered_url
    )


if __name__ == "__main__":
    app.run(debug=True)
