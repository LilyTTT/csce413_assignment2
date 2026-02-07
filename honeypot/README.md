## Honeypot

The honeypot service was implemented using the default templates and `paramiko`, impersonating an SSH server, logging authentication attemps and rejecting all logins.

### honeypot.py
Default Configurations:
- Listen address: 0.0.0.0 (any)
- Listen port: 22 (inside container, mapped to 2222 on host)
- SSH banner: OpenSSH_8.9p1 Ubuntu-3ubuntu0.13 (grabbed from secret SSH)

The server listens for incoming connections and mimics a real service by sending a valid banner. Scanning the honeypot port and the secret ssh port gives the exact same response.

Behavior:
- One-time RSA hostkey generated on container startup
- Logs all username/password attempts
- Logs source network and port of connection attemps
- Always fails authentication attemps

### Example Usage 
From host:
`ssh -p 2222 user@localhost`