## Port Knocking

Port knocking was implemented with Linux `iptables` and the `recent` module (suggested by the repo README.md). The protected service is only accessible after a conseutive ports have been knocked in order within a specified time window.

### Files
#### Server Side (knock_server.py)
Default configurations
- Sequence: 1234, 5678, 9012
- protected port: 2222
- time window: 10 seconds

The server side uses `iptables` with `recent` module to track knock progress & enforce a time window, only allowing access after the knocks have happened in the expected order.

- Protected port is blocked by default
- Knocks are recorded using `--set` in `iptables -m recent`
- Knocks are validated using `--rcheck`

#### Client Side (knock_client.py)
Send a sequence of TCP connection attempts (knocks) to the target host.
`--check` flag can be used to test connectivity to the protected port after knocking

### Example usage
```bash
python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012 --check
```
