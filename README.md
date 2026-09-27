# Country Subscription Builder

Collects public V2Ray/Xray subscription sources, resolves each node's endpoint,
and assigns the country from multiple independent GeoIP providers.

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
3. Query multiple GeoIP providers.
4. Combine independent results using weighted consensus.
5. Cache the result.
6. Replace the original remark with `XX 🇽🇽`.

This means a source saying `RU` does not force the result to be Russia.

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
