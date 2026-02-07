# Honeypot Analysis

## Summary of Observed Attacks
Example logs of suspicious activities:
`
2026-02-07 01:34:16,438 - INFO - Connection from 172.20.0.1:56356
2026-02-07 01:34:16,518 - ERROR - Error handling 172.20.0.1: Error reading SSH protocol banner
2026-02-07 01:34:16,526 - INFO - Connection closed for 172.20.0.1
2026-02-07 01:34:41,399 - INFO - Connection from 172.20.0.1:50742
2026-02-07 01:35:05,712 - WARNING - SSH login attempt | user='user' password='test1'
2026-02-07 01:35:08,977 - WARNING - SSH login attempt | user='user' password='test2'
2026-02-07 01:35:12,976 - WARNING - SSH login attempt | user='user' password='test3'
2026-02-07 01:35:13,073 - INFO - Connection closed for 172.20.0.1
`

The the above logs shows a scan & 3 log in attempts.

## Notable Patterns
All activities are coming from the same network address, which is worth investiagting further (it's the Docker bridge network)

## Recommendations
(If those logs were found in a real honeypot) 
- Monitor repeated login attempts
- Monitor IPs that frequently appear in logs
- Analyze username & passowrd patterns to potentially identify attacker