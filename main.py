import base64
import ipaddress
import json
import re
import socket
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import requests


# ============================================================
# SETTINGS
# ============================================================

OUTPUT_DIR = Path("output")
CACHE_FILE = Path("geo_cache.json")

REQUEST_TIMEOUT = 20
RETRIES = 3
GEO_BATCH_SIZE = 100
CACHE_TTL = 7 * 24 * 60 * 60

# Public collector sources.
# Source metadata is NEVER trusted for the final country.
SOURCES = [
    {
        "name": "au1rxx-country",
        "kind": "au1rxx_country",
        "url": "https://api.github.com/repos/Au1rxx/free-vpn-subscriptions/contents/output/by-country",
    },
    {
        "name": "radikal-secure",
        "kind": "plain",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt",
    },
    {
        "name": "radikal-all",
        "kind": "plain",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    },
    {
        "name": "mehrtat-vless",
        "kind": "plain",
        "url": "https://raw.githubusercontent.com/mehrtat/vless-collector/main/vless.txt",
    },
    {
        "name": "mohammadbahemmat",
        "kind": "plain",
        "url": "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/all_servers.txt",
    },
    {
        "name": "kasesm",
        "kind": "plain",
        "url": "https://raw.githubusercontent.com/kasesm/Free-Config/main/all_raw.txt",
    },
    {
        "name": "alirewa",
        "kind": "plain",
        "url": "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",
    },
    {
        "name": "patterniha",
        "kind": "plain",
        "url": "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
    },
]


# ============================================================
# HTTP
# ============================================================

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "country-subscription-builder/2.0",
    "Accept": "*/*",
})


def get(url, **kwargs):
    last_error = None

    for attempt in range(1, RETRIES + 1):
        try:
            response = SESSION.get(
                url,
                timeout=REQUEST_TIMEOUT,
                **kwargs,
            )
            response.raise_for_status()
            return response
        except Exception as exc:
            last_error = exc
            if attempt < RETRIES:
                time.sleep(attempt * 2)

    raise RuntimeError(f"GET failed: {url} -> {last_error}")


# ============================================================
# COUNTRY / FLAG
# ============================================================

def country_flag(code):
    if not code or not re.fullmatch(r"[A-Z]{2}", code.upper()):
        return "🏳️"

    code = code.upper()
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)


def country_remark(code):
    code = (code or "").upper()

    if re.fullmatch(r"[A-Z]{2}", code):
        return f"{code} {country_flag(code)}"

    return "UN 🌐"


# ============================================================
# SUBSCRIPTION DECODING
# ============================================================

PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "ssr://",
    "hy2://",
    "hysteria2://",
    "tuic://",
    "socks://",
    "socks5://",
)


def decode_base64_text(data):
    compact = re.sub(r"\s+", "", data.strip())

    if not compact:
        return data

    candidates = [
        compact,
        compact + "=" * (-len(compact) % 4),
    ]

    for candidate in candidates:
        try:
            raw = base64.urlsafe_b64decode(candidate)
            text = raw.decode("utf-8", errors="strict")

            if any(p in text.lower() for p in PROTOCOLS):
                return text
        except Exception:
            pass

    return data


def expand_source_text(raw):
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")

    # Most sources are already plain text.
    if any(p in raw.lower() for p in PROTOCOLS):
        return raw

    decoded = decode_base64_text(raw)

    if decoded != raw:
        return decoded

    return raw


def normalize_config_lines(text):
    text = expand_source_text(text)

    result = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        # Some collectors put several URI configs on one line.
        matches = re.findall(
            r"(?:vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic|socks5?)://\S+",
            line,
            flags=re.I,
        )

        if matches:
            result.extend(matches)
        elif line.lower().startswith(PROTOCOLS):
            result.append(line)

    return result


# ============================================================
# DEDUPLICATION
# ============================================================

def strip_remark(config):
    if "#" in config:
        return config.split("#", 1)[0]
    return config


def config_key(config):
    """
    Deduplicate the same node even if different sources gave it
    different remarks.
    """
    return strip_remark(config).strip()


# ============================================================
# ADDRESS EXTRACTION
# ============================================================

def extract_address(config):
    config = config.strip()

    # URI formats.
    if "://" in config:
        try:
            parsed = urlsplit(config)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass

    # VMess may occasionally be presented as JSON.
    try:
        obj = json.loads(config)
    except Exception:
        return None

    possible_keys = {
        "address",
        "server",
        "host",
        "add",
        "domain",
        "ip",
        "ip_address",
    }

    def walk(value):
        if isinstance(value, dict):
            for key in possible_keys:
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.strip()

            for child in value.values():
                found = walk(child)
                if found:
                    return found

        elif isinstance(value, list):
            for child in value:
                found = walk(child)
                if found:
                    return found

        return None

    return walk(obj)


# ============================================================
# DNS
# ============================================================

def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def resolve_all(address):
    if not address:
        return []

    try:
        ip = ipaddress.ip_address(address)
        return [address] if is_public_ip(address) else []
    except ValueError:
        pass

    ips = []

    try:
        results = socket.getaddrinfo(
            address,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for item in results:
            candidate = item[4][0]
            if is_public_ip(candidate):
                ips.append(candidate)
    except Exception:
        pass

    return list(dict.fromkeys(ips))


# ============================================================
# CACHE
# ============================================================

def load_cache():
    if not CACHE_FILE.exists():
        return {}

    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))

        if not isinstance(data, dict):
            return {}

        return data
    except Exception:
        return {}


def save_cache(cache):
    CACHE_FILE.write_text(
        json.dumps(
            cache,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def cache_valid(entry):
    if not isinstance(entry, dict):
        return False

    checked_at = entry.get("checked_at", 0)

    try:
        return time.time() - float(checked_at) < CACHE_TTL
    except Exception:
        return False


# ============================================================
# GEO PROVIDER: countries.dev
# ============================================================

def geo_countries_dev(ips):
    results = {}

    for start in range(0, len(ips), GEO_BATCH_SIZE):
        batch = ips[start:start + GEO_BATCH_SIZE]

        try:
            response = SESSION.post(
                "https://countries.dev/ip",
                json=batch,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue

                    ip = item.get("ip") or item.get("address")
                    code = (
                        item.get("country_code")
                        or item.get("countryCode")
                        or item.get("iso_code")
                        or item.get("isoCode")
                    )

                    if ip and code:
                        results[str(ip)] = {
                            "country": str(code).upper(),
                            "provider": "countries.dev",
                        }

            elif isinstance(data, dict):
                for ip, item in data.items():
                    if isinstance(item, dict):
                        code = (
                            item.get("country_code")
                            or item.get("countryCode")
                            or item.get("iso_code")
                            or item.get("isoCode")
                        )

                        if code:
                            results[str(ip)] = {
                                "country": str(code).upper(),
                                "provider": "countries.dev",
                            }

                    elif isinstance(item, str):
                        results[str(ip)] = {
                            "country": item.upper(),
                            "provider": "countries.dev",
                        }

        except Exception as exc:
            print(f"[GEO] countries.dev failed: {exc}")

        time.sleep(0.25)

    return results


# ============================================================
# GEO PROVIDER: ipwho.is
# ============================================================

def geo_ipwho(ip):
    try:
        response = SESSION.get(
            f"https://ipwho.is/{ip}",
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        if not data.get("success", True):
            return None

        code = data.get("country_code")

        if not code:
            return None

        connection = data.get("connection") or {}

        return {
            "country": str(code).upper(),
            "country_name": data.get("country"),
            "city": data.get("city"),
            "region": data.get("region"),
            "asn": connection.get("asn"),
            "org": connection.get("org"),
            "isp": connection.get("isp"),
            "source": "ipwho.is",
        }

    except Exception as exc:
        print(f"[GEO] ipwho.is {ip}: {exc}")
        return None


# ============================================================
# GEO PROVIDER: ipapi.co
# ============================================================

def geo_ipapi(ip):
    try:
        response = SESSION.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        code = data.get("country_code")

        if not code:
            return None

        return {
            "country": str(code).upper(),
            "country_name": data.get("country_name"),
            "city": data.get("city"),
            "region": data.get("region"),
            "asn": data.get("asn"),
            "org": data.get("org"),
            "isp": data.get("org"),
            "source": "ipapi.co",
        }

    except Exception as exc:
        print(f"[GEO] ipapi.co {ip}: {exc}")
        return None


# ============================================================
# GEO RESOLUTION / CONSENSUS
# ============================================================

def merge_geo(ip, countries_result, cache):
    """
    Build a multi-provider result.

    Weight:
      countries.dev = 3
      ipwho.is      = 3
      ipapi.co      = 3

    Additional evidence:
      ASN/org is kept for diagnostics but does NOT override
      multiple independent GeoIP results.
    """

    if ip in cache and cache_valid(cache[ip]):
        return cache[ip]

    votes = Counter()
    provider_results = {}

    countries_item = countries_result.get(ip)

    if countries_item:
        code = countries_item.get("country")
        if code:
            votes[code] += 3
            provider_results["countries.dev"] = code

    who = geo_ipwho(ip)

    if who and who.get("country"):
        code = who["country"]
        votes[code] += 3
        provider_results["ipwho.is"] = code

    api = geo_ipapi(ip)

    if api and api.get("country"):
        code = api["country"]
        votes[code] += 3
        provider_results["ipapi.co"] = code

    if votes:
        ordered = votes.most_common()

        best_code, best_score = ordered[0]
        total_score = sum(votes.values())

        # Confidence is based on independent provider agreement.
        confidence = round(best_score / total_score, 4)

        # A unanimous 3-provider result gets a hard confidence floor.
        if len(provider_results) >= 3 and len(votes) == 1:
            confidence = max(confidence, 0.98)

        result = {
            "country": best_code,
            "confidence": confidence,
            "votes": dict(votes),
            "providers": provider_results,
            "ipwho": who or {},
            "ipapi": api or {},
            "checked_at": int(time.time()),
        }

        cache[ip] = result
        return result

    result = {
        "country": None,
        "confidence": 0.0,
        "votes": {},
        "providers": {},
        "ipwho": who or {},
        "ipapi": api or {},
        "checked_at": int(time.time()),
    }

    cache[ip] = result
    return result


# ============================================================
# NODE GEOLOCATION
# ============================================================

def geolocate_node(address, cache, countries_results):
    ips = resolve_all(address)

    if not ips:
        return {
            "country": None,
            "confidence": 0.0,
            "ips": [],
            "details": {},
        }

    details = {}
    country_votes = Counter()

    for ip in ips:
        geo = merge_geo(ip, countries_results, cache)
        details[ip] = geo

        code = geo.get("country")
        confidence = float(geo.get("confidence", 0))

        if code:
            # Multiple A/AAAA addresses get weighted by confidence.
            country_votes[code] += confidence

    if not country_votes:
        return {
            "country": None,
            "confidence": 0.0,
            "ips": ips,
            "details": details,
        }

    best_country, weighted_score = country_votes.most_common(1)[0]
    total = sum(country_votes.values())

    confidence = weighted_score / total if total else 0.0

    return {
        "country": best_country,
        "confidence": round(confidence, 4),
        "ips": ips,
        "details": details,
    }


# ============================================================
# REMARK REPLACEMENT
# ============================================================

def replace_uri_remark(config, remark):
    base = config.split("#", 1)[0]
    return base + "#" + quote(remark, safe="")


def replace_vmess_remark(config, remark):
    try:
        prefix = "vmess://"
        encoded = config[len(prefix):]

        decoded = base64.urlsafe_b64decode(
            encoded + "=" * (-len(encoded) % 4)
        ).decode("utf-8")

        obj = json.loads(decoded)

        if isinstance(obj, dict):
            obj["ps"] = remark

            payload = json.dumps(
                obj,
                ensure_ascii=False,
                separators=(",", ":"),
            )

            new_encoded = base64.urlsafe_b64encode(
                payload.encode("utf-8")
            ).decode("ascii")

            return prefix + new_encoded

    except Exception:
        pass

    return replace_uri_remark(config, remark)


def replace_remark(config, remark):
    lower = config.lower().strip()

    if lower.startswith("vmess://"):
        return replace_vmess_remark(config, remark)

    if any(lower.startswith(p) for p in PROTOCOLS):
        return replace_uri_remark(config, remark)

    return config


# ============================================================
# SOURCE FETCHING
# ============================================================

def fetch_au1rxx():
    """
    Au1rxx publishes country shards. We use the shards only as
    additional source material. Their country name is NOT trusted
    for the final output; every node is geolocated again.
    """

    response = get(
        "https://api.github.com/repos/Au1rxx/free-vpn-subscriptions/contents/output/by-country",
        headers={"Accept": "application/vnd.github+json"},
    )

    items = response.json()

    configs = []

    for item in items:
        name = item.get("name", "")

        if not re.fullmatch(r"v2ray-base64-[A-Z]{2}\.txt", name):
            continue

        url = item.get("download_url")

        if not url:
            continue

        try:
            raw = get(url).text
            configs.extend(normalize_config_lines(raw))
        except Exception as exc:
            print(f"[SOURCE] Au1rxx {name}: {exc}")

    return configs


def fetch_plain_source(source):
    response = get(source["url"])
    return normalize_config_lines(response.text)


def fetch_all_sources():
    configs = []

    for source in SOURCES:
        print()
        print(f"[SOURCE] {source['name']}")

        try:
            if source["kind"] == "au1rxx_country":
                items = fetch_au1rxx()
            else:
                items = fetch_plain_source(source)

            print(f"[SOURCE] {source['name']}: {len(items)} configs")
            configs.extend(items)

        except Exception as exc:
            print(f"[SOURCE] FAILED {source['name']}: {exc}")

    # Deduplicate by node endpoint, ignoring old remarks.
    unique = {}
    for config in configs:
        key = config_key(config)
        if key:
            unique.setdefault(key, config)

    print()
    print(f"[+] Raw configs: {len(configs)}")
    print(f"[+] Unique configs: {len(unique)}")

    return list(unique.values())


# ============================================================
# OUTPUT
# ============================================================

def write_output(country_nodes, all_nodes):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Remove old country files so stale countries disappear.
    for path in OUTPUT_DIR.glob("*.txt"):
        path.unlink()

    # all.txt: one URI per line, ready as a plain subscription.
    (OUTPUT_DIR / "all.txt").write_text(
        "\n".join(all_nodes) + ("\n" if all_nodes else ""),
        encoding="utf-8",
    )

    # all-base64.txt: convenient Base64 subscription.
    encoded_all = base64.b64encode(
        ("\n".join(all_nodes) + ("\n" if all_nodes else "")).encode("utf-8")
    ).decode("ascii")

    (OUTPUT_DIR / "all-base64.txt").write_text(
        encoded_all + "\n",
        encoding="utf-8",
    )

    for code, nodes in sorted(country_nodes.items()):
        if not re.fullmatch(r"[A-Z]{2}", code):
            continue

        text = "\n".join(nodes) + "\n"

        (OUTPUT_DIR / f"{code}.txt").write_text(
            text,
            encoding="utf-8",
        )

        encoded = base64.b64encode(
            text.encode("utf-8")
        ).decode("ascii")

        (OUTPUT_DIR / f"{code}-base64.txt").write_text(
            encoded + "\n",
            encoding="utf-8",
        )


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 70)
    print("Country Subscription Builder 2.0")
    print("Multi-source + multi-GeoIP + dynamic country support")
    print("=" * 70)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    cache = load_cache()

    configs = fetch_all_sources()

    if not configs:
        raise RuntimeError("No configs were collected.")

    # Extract and resolve every unique address first.
    config_addresses = {}
    all_ips = []

    for index, config in enumerate(configs, 1):
        address = extract_address(config)
        config_addresses[config] = address

        if address:
            ips = resolve_all(address)
            all_ips.extend(ips)

        if index % 500 == 0:
            print(f"[DNS] prepared {index}/{len(configs)}")

    all_ips = list(dict.fromkeys(all_ips))

    print()
    print(f"[+] Unique public IPs: {len(all_ips)}")
    print(f"[+] Cached IPs: {sum(1 for ip in all_ips if ip in cache and cache_valid(cache[ip]))}")

    uncached_ips = [
        ip
        for ip in all_ips
        if not (ip in cache and cache_valid(cache[ip]))
    ]

    print(f"[+] New GeoIP lookups: {len(uncached_ips)}")

    # Fast batch provider first.
    countries_results = {}

    if uncached_ips:
        countries_results = geo_countries_dev(uncached_ips)

    # Build the final node country.
    country_nodes = defaultdict(list)
    all_nodes = []

    stats = Counter()
    node_count = len(configs)

    for index, config in enumerate(configs, 1):
        address = config_addresses.get(config)

        geo = geolocate_node(
            address,
            cache,
            countries_results,
        )

        code = geo.get("country")
        confidence = float(geo.get("confidence", 0))

        if not code:
            code = "UN"
            stats["unknown"] += 1
        elif confidence >= 0.98:
            stats["high_confidence"] += 1
        elif confidence >= 0.66:
            stats["medium_confidence"] += 1
        else:
            stats["low_confidence"] += 1

        remark = country_remark(code)
        result = replace_remark(config, remark)

        all_nodes.append(result)

        if code != "UN":
            country_nodes[code].append(result)

        if index % 100 == 0 or index == node_count:
            print(
                f"[GEO] {index}/{node_count} | "
                f"countries={len(country_nodes)} | "
                f"unknown={stats['unknown']}"
            )

    # Final deduplication after remark replacement.
    all_nodes = list(dict.fromkeys(all_nodes))

    for code in list(country_nodes):
        country_nodes[code] = list(dict.fromkeys(country_nodes[code]))

    save_cache(cache)
    write_output(country_nodes, all_nodes)

    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)
    print(f"Total nodes: {len(all_nodes)}")
    print(f"Countries: {len(country_nodes)}")
    print(f"High confidence: {stats['high_confidence']}")
    print(f"Medium confidence: {stats['medium_confidence']}")
    print(f"Low confidence: {stats['low_confidence']}")
    print(f"Unknown: {stats['unknown']}")
    print()
    print("Output:")
    print("  output/all.txt")
    print("  output/all-base64.txt")
    print("  output/XX.txt")
    print("  output/XX-base64.txt")
    print()
    print("Geo cache:")
    print(f"  {CACHE_FILE}")


if __name__ == "__main__":
    main()
