import base64
import json
import re
from pathlib import Path
from urllib.request import Request, urlopen

SOURCE_API = (
    "https://api.github.com/repos/"
    "Au1rxx/free-vpn-subscriptions/contents/output/by-country"
)

OUTPUT_DIR = Path("output")

# Country code -> flag
FLAGS = {
    "AE": "🇦🇪", "AT": "🇦🇹", "AU": "🇦🇺", "BE": "🇧🇪",
    "BG": "🇧🇬", "BR": "🇧🇷", "CA": "🇨🇦", "CH": "🇨🇭",
    "CN": "🇨🇳", "CZ": "🇨🇿", "DE": "🇩🇪", "DK": "🇩🇰",
    "EE": "🇪🇪", "ES": "🇪🇸", "FI": "🇫🇮", "FR": "🇫🇷",
    "GB": "🇬🇧", "GR": "🇬🇷", "HK": "🇭🇰", "HU": "🇭🇺",
    "ID": "🇮🇩", "IE": "🇮🇪", "IL": "🇮🇱", "IN": "🇮🇳",
    "IR": "🇮🇷", "IT": "🇮🇹", "JP": "🇯🇵", "KR": "🇰🇷",
    "KZ": "🇰🇿", "LT": "🇱🇹", "LU": "🇱🇺", "LV": "🇱🇻",
    "MY": "🇲🇾", "MX": "🇲🇽", "NL": "🇳🇱", "NO": "🇳🇴",
    "NZ": "🇳🇿", "PL": "🇵🇱", "PT": "🇵🇹", "RO": "🇷🇴",
    "RU": "🇷🇺", "SE": "🇸🇪", "SG": "🇸🇬", "SI": "🇸🇮",
    "SK": "🇸🇰", "TH": "🇹🇭", "TR": "🇹🇷", "TW": "🇹🇼",
    "UA": "🇺🇦", "US": "🇺🇸", "VN": "🇻🇳", "ZA": "🇿🇦",
}


def get_json(url):
    req = Request(
        url,
        headers={
            "User-Agent": "country-subscription-builder",
            "Accept": "application/vnd.github+json",
        },
    )

    with urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode())


def country_remark(code):
    return f"{code} {FLAGS.get(code, '')}".strip()


def decode_subscription(data):
    """
    Decode the base64 subscription.

    Supports:
      - normal base64
      - base64url
      - plain text fallback
    """

    data = data.strip()

    # Remove possible whitespace
    compact = re.sub(r"\s+", "", data)

    # Try normal/base64url decoding
    for candidate in (compact, compact + "=" * (-len(compact) % 4)):
        try:
            raw = base64.urlsafe_b64decode(candidate)
            text = raw.decode("utf-8")

            # Make sure it actually looks like a subscription
            if (
                "vless://" in text
                or "vmess://" in text
                or "trojan://" in text
                or "ss://" in text
                or "hy2://" in text
                or "hysteria2://" in text
            ):
                return text
        except Exception:
            pass

    # Maybe source is already plain text
    return data


def encode_subscription(text):
    raw = text.encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def set_uri_remark(uri, remark):
    """
    Replace everything after # with the requested remark.
    """

    if "#" in uri:
        uri = uri.split("#", 1)[0]

    # URL encode the remark.
    from urllib.parse import quote

    return f"{uri}#{quote(remark, safe='')}"


def set_vmess_remark(uri, remark):
    """
    VMess URI:

    vmess://BASE64(JSON)

    Change JSON 'ps' field.
    """

    try:
        encoded = uri[len("vmess://"):].strip()

        decoded = base64.urlsafe_b64decode(
            encoded + "=" * (-len(encoded) % 4)
        ).decode("utf-8")

        config = json.loads(decoded)

        config["ps"] = remark

        new_json = json.dumps(
            config,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        new_encoded = base64.urlsafe_b64encode(
            new_json.encode("utf-8")
        ).decode("ascii")

        return f"vmess://{new_encoded}"

    except Exception:
        return uri


def modify_remark(uri, remark):
    uri = uri.strip()

    if not uri:
        return None

    if uri.startswith("vmess://"):
        return set_vmess_remark(uri, remark)

    if (
        uri.startswith("vless://")
        or uri.startswith("trojan://")
        or uri.startswith("ss://")
        or uri.startswith("hy2://")
        or uri.startswith("hysteria2://")
    ):
        return set_uri_remark(uri, remark)

    return uri


def process_country(code, raw_data):
    remark = country_remark(code)

    decoded = decode_subscription(raw_data)

    lines = decoded.splitlines()

    output = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        # Ignore comments / metadata
        if line.startswith("#"):
            continue

        modified = modify_remark(line, remark)

        if modified:
            output.append(modified)

    # Remove duplicates while preserving order
    output = list(dict.fromkeys(output))

    if not output:
        return 0

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Base64 subscription
    encoded = encode_subscription("\n".join(output) + "\n")

    (OUTPUT_DIR / f"{code}.txt").write_text(
        encoded + "\n",
        encoding="utf-8",
    )

    # Plain URI version too
    (OUTPUT_DIR / f"{code}-plain.txt").write_text(
        "\n".join(output) + "\n",
        encoding="utf-8",
    )

    print(f"{code}: {len(output)} nodes -> {remark}")

    return len(output)


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    files = get_json(SOURCE_API)

    total = 0
    countries = 0

    for item in files:

        name = item.get("name", "")

        match = re.fullmatch(
            r"v2ray-base64-([A-Z]{2})\.txt",
            name,
        )

        if not match:
            continue

        code = match.group(1)

        try:
            raw_url = item["download_url"]

            req = Request(
                raw_url,
                headers={"User-Agent": "country-subscription-builder"},
            )

            with urlopen(req, timeout=30) as response:
                raw_data = response.read().decode("utf-8")

            count = process_country(code, raw_data)

            if count:
                total += count
                countries += 1

        except Exception as e:
            print(f"[ERROR] {code}: {e}")

    print()
    print(f"Countries: {countries}")
    print(f"Total nodes: {total}")


if __name__ == "__main__":
    main()
