# v4rayy

Auto-updated, country-sorted V2Ray / Xray subscription links, rebuilt every hour with GitHub Actions.

اشتراک‌های V2Ray / Xray که بر اساس کشور دسته‌بندی شده‌اند و هر ساعت به‌صورت خودکار آپدیت می‌شوند.

---

## Subscription links / لینک‌های اشتراک

Copy a link into your client (v2rayNG, Hiddify, Streisand, NekoBox, v2rayN, ...) as a subscription URL.

| What | Plain | Base64 |
|------|-------|--------|
| All countries | [`all.txt`](https://raw.githubusercontent.com/iErfun/v4rayy/main/output/all.txt) | [`all-base64.txt`](https://raw.githubusercontent.com/iErfun/v4rayy/main/output/all-base64.txt) |
| One country (e.g. Germany) | [`DE.txt`](https://raw.githubusercontent.com/iErfun/v4rayy/main/output/DE.txt) | [`DE-base64.txt`](https://raw.githubusercontent.com/iErfun/v4rayy/main/output/DE-base64.txt) |

For any other country, replace `DE` with its ISO 3166-1 alpha-2 code (`US`, `NL`, `TR`, `FI`, ...). Only countries that currently have nodes get a file; see the [`output/`](output/) folder for the full list.

```
https://raw.githubusercontent.com/iErfun/v4rayy/main/output/<COUNTRY_CODE>.txt
https://raw.githubusercontent.com/iErfun/v4rayy/main/output/<COUNTRY_CODE>-base64.txt
```

If your client doesn't accept the plain file, use the `-base64` version.

## How it works / چطور کار می‌کند

1. `main.py` downloads configs from several public collector repos (list in `SOURCES`).
2. It decodes subscriptions, splits lines, and extracts every `vless`, `vmess`, `trojan`, `ss`, `ssr`, `hy2`/`hysteria2`, `tuic` and `socks` URI.
3. Duplicates are removed by node endpoint, ignoring the old remark.
4. Each node's address is resolved via DNS (private/non-public IPs are skipped) and geolocated. The country that the source claims is **never trusted**; the country is decided by a weighted vote between several geo-IP providers (countries.dev, ip-api.com, ipwho.is, ipapi.co), with rate-limit handling and a per-run circuit breaker.
5. Results are cached in `geo_cache.json` for 7 days to avoid repeated lookups.
6. Every config's remark is rewritten to `CC 🏳️` (country code + flag), and files are written to `output/`.
7. The workflow in `.github/workflows/update.yml` runs this at minute 17 of every hour (and on manual dispatch), then commits any changes.

## Run it yourself / اجرای محلی

Requires Python 3.9+ and `requests`.

```bash
pip install requests
python main.py
```

Output is written to `output/`, and the geo cache to `geo_cache.json`.

To run your own copy on GitHub: fork the repo, enable Actions, and make sure the workflow has write access to contents (already set via `permissions: contents: write`).

## Repository layout

```
.
├── main.py                      # collector, geolocator, writer
├── geo_cache.json               # cached geo-IP results (auto-updated)
├── output/                      # generated subscriptions (auto-updated)
│   ├── all.txt / all-base64.txt
│   └── XX.txt / XX-base64.txt   # one pair per country
└── .github/workflows/update.yml # hourly build + commit
```

## Warning / هشدار

- These configs come from **third-party public sources**. They are untrusted: the node operators can see and tamper with unencrypted traffic. Many nodes use `security=none`.
- Don't use them for banking, logins, or anything sensitive.
- Nodes are not health-checked, so expect many of them to be slow or dead.
- Country labels are best-effort geo-IP guesses and can be wrong (CDNs, proxies, anycast).
- Use at your own risk and follow the laws that apply to you.

## Credits

Configs are gathered from public repos including Au1rxx, 0xRadikal, mehrtat, MohammadBahemmat, kasesm, Alirewa and patterniha. Thanks to all of them.
