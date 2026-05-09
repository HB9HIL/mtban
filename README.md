# mtban

Manages MikroTik firewall address-list entries via the RouterOS REST API (RouterOS 7+).
Can be used standalone or as a fail2ban action as it was designed for.

## Install

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://hb9hil.github.io/mtban/pubkey.asc \
  | sudo tee /etc/apt/keyrings/mtban.asc > /dev/null

sudo tee /etc/apt/sources.list.d/mtban.sources > /dev/null <<EOF
Types: deb
URIs: https://hb9hil.github.io/mtban
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/mtban.asc
EOF

sudo apt update
sudo apt install mtban
```

## Configure

Edit `/etc/mtban/mtban.conf` (created automatically on install, mode `0600`):

```
url      = http://[mikrotik-ip]:[www-service-port]
username = mtban
password = your-api-secret
```

### MikroTik side

Create a dedicated API user with limited permissions and a firewall
rule that drops traffic from the address-list:

```
/user/group 
add name=mtban policy=read,write,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon
/user 
add name=mtban group=mtban password="your-api-secret"

/ip/firewall/raw
add action=drop chain=prerouting comment=mtban-blocked src-address-list=mtban-blocked
add action=drop chain=prerouting comment=mtban-blocked dst-address-list=mtban-blocked
```

## Standalone usage

```bash
mtban ban 198.51.100.1 --timeout 3600
mtban unban 198.51.100.1
mtban ban 198.51.100.1 --list mtban-blocked --comment "manual block"
```

## Use with fail2ban

Create `/etc/fail2ban/action.d/mtban.conf`:

```ini
[Definition]
actionban     = /usr/bin/mtban ban <ip> --list <list> --timeout <bantime> --comment "fail2ban <name>"
actionprolong = /usr/bin/mtban ban <ip> --list <list> --timeout <bantime> --comment "fail2ban <name>"
actionunban   = /usr/bin/mtban unban <ip> --list <list>

[Init]
list = blocked
```

In `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
bantime              = 12h
bantime.increment    = true
bantime.multiplier   = 1 2 4 8 16 32 64
bantime.overalljails = true
findtime             = 10m
maxretry             = 5

[sshd]
enabled = true
action  = mtban[name=my-host-sshd]
```

Reload: `sudo fail2ban-client reload`

The action's bantime is taken from fail2ban's `<bantime>` and passed to
MikroTik as the address-list timeout, so both sides expire together.

## Local development

```bash
cat > /tmp/mtban.conf <<EOF
url = http://192.0.2.1:80
username = mtban
password = your-api-secret
EOF

go run . ban 198.51.100.1 --config /tmp/mtban.conf --timeout 60
go run . unban 198.51.100.1 --config /tmp/mtban.conf

# or build once
go build -o dist/mtban .
./dist/mtban ban 198.51.100.1 --config /tmp/mtban.conf --timeout 60
./dist/mtban unban 198.51.100.1 --config /tmp/mtban.conf
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.