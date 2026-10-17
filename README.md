# piremote

Remote shell to my Raspberry Pi from my Mac, from anywhere, over a Cloudflare Tunnel.

`piws.py` is the connection helper: it resolves the Pi's hostname through DNS-over-HTTPS (so it works even on Wi-Fi networks that hijack or block normal DNS), then carries the SSH session through the tunnel. No admin rights needed on the Mac, no router or firewall changes on the Pi side.

## Setup (Mac)

Run the setup line Instinct gave you, or manually:

1. Download the helper: `curl -sL https://raw.githubusercontent.com/Greenisus1/piremote/main/piws.py -o ~/CrunchByte/PiRemote/piws.py`
2. Add this to `~/.ssh/config`:

```
Host pi
  HostName ssh.crunchbytes.dpdns.org
  User root
  ProxyCommand python3 ~/CrunchByte/PiRemote/piws.py %h
```

3. Connect: `ssh pi`

Requires python3 (stock on macOS). Login is by SSH key; the Pi's password login should be disabled once the key works.

Built with AI assistance from my design.
