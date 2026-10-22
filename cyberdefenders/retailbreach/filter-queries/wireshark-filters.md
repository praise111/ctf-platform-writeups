# Wireshark Display Filters — RetailBreach

Filters used during the investigation, in order of use.

## Orientation
```
http
```
Reduce the capture to HTTP so the application-layer activity is readable. (Protocol Hierarchy showed HTTP as the dominant cleartext protocol; Endpoints showed the three hosts in play.)

## Q1 — Find the attacker (directory fuzzing → 404 flood)
```
http and (_ws.col.info == "HTTP/1.1 404 Not Found  (text/html)")
```
Isolates the 404 responses; nearly all are returned to the fuzzing host (`111.224.180.128`).

## Q2 — Identify the tool
Inspect the HTTP request headers of the fuzzing traffic and read the `User-Agent` field (`gobuster/3.6`). No filter beyond selecting one of the attacker's requests.

## Q3 — Locate the XSS injection
```
http.request.method == "POST" and frame contains "script"
```
Isolates the POST to `reviews.php` carrying the script payload; Follow HTTP Stream (`tcp.stream eq 96`) to read it in full.

## Q4 — Admin's first visit after injection
```
(http) && (ip.addr == 135.143.142.5) and frame contains "admin"
```
Filters the victim admin host's admin-area traffic to find the visit in the `12:09` (UTC) window.

## Q5 — Stolen session token
Compare the `Cookie: PHPSESSID=...` value in the admin's legitimate traffic against the one presented from the attacker host at `/admin/dashboard.php`. (Inspect the HTTP headers; no single filter — the point is the cross-IP match.)

## Q6 — Exploited script
```
(http) && (ip.addr == 111.224.180.128) and frame contains "/admin/"
```
Shows the attacker's admin-area requests, including the traversal against `log_viewer.php`.

## Q7 — Sensitive-file payload
Read the full request URI of the abnormal `log_viewer.php` request:
```
GET /admin/log_viewer.php?file=../../../../../etc/passwd
```

---

### Handy variants
```
# All traffic to/from the attacker
ip.addr == 111.224.180.128

# Follow a specific conversation
tcp.stream eq 96

# Any request whose URI shows traversal
http.request.uri contains "../"
```
