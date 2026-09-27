# Country Subscription Builder

Collects public V2Ray/Xray subscription sources, resolves each node's endpoint,
and assigns the country from multiple independent GeoIP providers.

**v2.1** — rate-limit safe: batch providers first (`countries.dev` + `ip-api.com`),
single providers only when needed, exponential backoff + circuit breaker on 429.

## Sources

- Au1rxx/free-vpn-subscriptions
- 0xRadikal/Free-v2ray-Configs
- mehrtat/vless-collector
- MohammadBahemmat/V2ray-Collector
- kasesm/Free-Config
- Alirewa/V2ray-Configs
- patterniha/Free-Configs

The source remark/country is not trusted for the final location.

## Location logic

For every node:

1. Extract hostname/IP.
2. Resolve all public A/AAAA addresses.
3. Query batch GeoIP providers first (`countries.dev`, `ip-api.com`).
4. Only if batch consensus is weak, query single-IP providers (`ipwho.is`, `ipapi.co`) with rate limiting.
5. Combine independent results using weighted consensus.
6. Cache the result (7 days).
7. Replace the original remark with `XX 🇽🇽`.

This means a source saying `RU` does not force the result to be Russia.

## Rate-limit handling

- Batch endpoints preferred (fewer requests).
- Delays between calls for single providers.
- Exponential backoff on HTTP 429.
- Circuit breaker: after several consecutive 429s a provider is disabled for the rest of the run.
- Cached IPs are never re-queried within TTL.

## Output

- `output/all.txt`
- `output/all-base64.txt`
- `output/DE.txt`
- `output/DE-base64.txt`
- etc.

Country files are created dynamically. There is no hard-coded country list.

## Important limitation

IP geolocation identifies the public endpoint IP. CDN, Cloudflare, Anycast,
reverse proxies and similar frontends can make the endpoint country differ from
the actual origin server country. No ordinary IP GeoIP service can reliably
recover a hidden origin from a CDN IP.

Public VPN configs are third-party data. Do not use unknown free nodes for
sensitive traffic or credentials.
