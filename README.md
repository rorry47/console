## Simple console in browse

<img src="https://github.com/rorry47/console/blob/main/console.jpg">

INSTALL

This script uses: Apache\Nginx, PHP 7.4+. 

Install: 
```
# Core network and diagnostics
sudo apt install -y whois dnsutils iputils-ping traceroute nmap curl

# For httping (often not in the database)
sudo apt install -y httping

# For GeoIP (unless you are using a ip-api.com API)
# But it's easier to pull through curl ip-api.com/json/ {ip}
sudo apt install -y geoip-bin

# To work with DNSSEC (often included in bind9-host or ldnsutils)
sudo apt install -y ldnsutils

# For specific port checks (nc - netcat)
sudo apt install -y netcat-openbsd
```


---

## Commands

## 🌐 Network Tools
| Command | Arguments | Description |
| :--- | :--- | :--- |
| `whois` | `[host]` | WHOIS lookup for domain or IP |
| `rdap` | `[host]` | Modern WHOIS (RDAP) lookup |
| `geoip` | `[host\|ip]` | Country, city, ISP, and ASN info |
| `headers` | `[host]` | Show HTTP response headers |
| `dnsbl` | `[ip]` | Check IP against spam blacklists |
| `dnssec` | `[domain]` | Check DNSSEC signature & chain of trust |
| `redirect` | `[url]` | Full redirect chain with status codes |
| `tech` | `[domain]` | Detect CMS, framework, server, CDN |
| `ping` | `[host]` | ICMP ping (4 packets) |
| `httping` | `[host]` | Performance check via HTTP |
| `dig` | `[host] [type]` | DNS lookup (A, MX, NS, TXT, etc.) |
| `nslookup`| `[host]` | Classic DNS lookup |
| `nmap` | `[host]` | Fast port scan (top ports) |
| `ssl` | `[host]` | TLS certificate details |
| `tracert` | `[host]` | Traceroute to destination |
| `ptr` | `[ip]` | Reverse DNS (PTR record) |
| `port` | `[host] [port]` | Check if a specific port is open |

## 🔐 Encoding & Crypto
*   `passgen [length]` — Generate a secure random password.
*   `hash <algo> <text>` — MD5, SHA1, SHA256, SHA512.
*   `base64 <encode|decode> <text>` — Base64 processing.
*   `urlencode` / `urldecode` — URL string manipulation.

## 🛰️ Proxy & System
*   `list <proxy|http|socks4|socks5>` — Fetch fresh proxy lists.
*   `myip` — Show your current IP address.
*   `uptime` / `date` — Server state and time.
*   `whoami` — Current console identity.

## ⌨️ Console Management
*   `su [name]` — Change display name.
*   `color [a|b|c|d|x|p]` — Switch UI color theme.
*   `clear` / `cls` — Wipe console output.
*   `exit` — Leave console (redirects to site).
