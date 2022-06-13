INSTALL

This script uses: Apache+Nginx, PHP 7.4. 

Linux utils: 
- whois
- ping 
- nslookup
- dig
- httping
- traceroute
- nmap
- curl
- openssl

____________________

UPDATES
____________________
| v1.2             |
| Date: 04.06.2022 |

- Fixed errors when entering a non-existent command.
- A command that was entered in capital letters is no longer considered an error.

____________________
| v1.1             |
| Date: 26.04.2022 |

- Commands added:
- - nmap [domain] [ip] - scan port server
- - list [proxy] [http] [socks4\5] - list IP-s and port or username proxy
- - nslookup [domain] [ip]  - check DNS for domain or ip
- - color [A][B][C][D][X][P][] - color themes console
- - info - simple text about console and contact
- - exit - close console end redirect to website

- Color themes are specified depending on the meaning of the letters. To switch to the standard one, you need to send the "color" command without specifying letters.

____________________
| v1.0             |
| Date: 19.04.2022 |

- Commands added:
- - whois [domain] [ip] - services for whois domain
- - ping [domain] [ip] - ping domain or ip
- - httping [domain] [ip] - httping domain or ip
- - dig [domain] - check dns record for domain
- - curl [domain] [ip] - server response
- - ssl [domain] [ip]  - check infossl sertificate
- - ptr [ip] - check PTR record for ip
