# PHP Server Dashboard

PHP Server Dashboard is a lightweight, single-file Linux resource monitor. The same `index.php` can run as a standalone dashboard, a central overview, or a reporting node. It does not require a database, Docker, Redis, or a separate application runtime.

## Current capabilities

- Live CPU usage, per-core load, temperatures, model information, and load averages
- RAM, swap, disk capacity, and disk I/O monitoring
- Network throughput, totals, interfaces, and local addresses
- Top processes with continuously sampled CPU and memory usage
- NVIDIA, Intel, and compatible GPU detection where vendor tools are available
- Operating system, kernel, architecture, uptime, and hardware details
- Server-Sent Events for live browser updates
- Central overview for multiple Linux servers
- Optional node groups in the central overview
- On-demand detailed telemetry so remote nodes normally send only lightweight summaries
- Automatic removal of nodes that stop reporting for three minutes
- Systemd and OpenRC Agent installation from the same PHP file
- Embedded per-machine settings; no companion configuration file is required

## How distributed monitoring works

Every machine receives a copy of `index.php`.

- The **central server** receives signed summary reports and displays all active nodes. It samples its own resources inside the web process and should not run an Agent that reports back to itself.
- A **reporting node** runs the same file as a small background Agent. It sends summary metrics at the configured interval.
- When an authenticated user opens a remote node, the central server temporarily asks that Agent for detailed process, hardware, disk, and interface data.
- Node state, browser sessions, and detail leases are held in SysV shared memory. They are intentionally ephemeral and are rebuilt after a reboot.

## Requirements

- Linux with `/proc` and `/sys`
- Nginx, Apache, or another PHP-capable web server
- PHP 8.1 or newer
- PHP extensions: `sysvshm`, `sysvsem`, and preferably `curl`
- Standard tools such as `ps`, `df`, `ip`, `lscpu`, and `getconf`
- Optional hardware tools: `lshw`, `nvidia-smi`, `intel_gpu_top`, or `xpu-smi`

The service installer also uses the PHP POSIX extension when available.

## Security setup

The public repository deliberately contains no usable credentials. Before deployment, replace these two placeholders near the top of `index.php`:

```php
$PROTECTED_PASSWORD = 'CHANGE_THIS_DASHBOARD_PASSWORD';
$MONITOR_CONNECTION_KEY = 'CHANGE_THIS_MONITOR_CONNECTION_KEY';
```

Use independent, randomly generated values. The dashboard refuses browser access, Agent startup, and report ingestion while either placeholder remains unchanged.

The current distributed protocol uses one connection key for every node attached to the same central dashboard. Keep customized copies out of Git and treat the deployed PHP file as a secret-bearing configuration file.

Recommended protections:

- Serve the dashboard only over HTTPS.
- Prefer Tailscale, Cloudflare Access, a VPN, or an IP allowlist for the browser interface.
- Make `index.php` readable only by root and the PHP/Agent group.
- Do not commit a configured production copy back to this repository.
- Use the CLI configuration workflow so the web process does not need write access to its own source file.

## Install a central server

Install the file into the web root. Adjust the PHP group and destination for your distribution:

```bash
sudo install -o root -g www-data -m 0640 index.php /var/www/html/index.php
sudo php /var/www/html/index.php --configure \
  --central-url=https://monitor.example.com \
  --node-id=au-mel-monitor \
  --group-name=Infrastructure \
  --sample-interval=3
```

Do not install the Agent service on the central server when its central URL points to itself. The overview appears automatically after the first remote node reports, and the central machine is included in that overview.

## Install a reporting node

Use the same monitor connection key as the central server, then configure and install the Agent:

```bash
sudo install -o root -g www-data -m 0640 index.php /var/www/html/index.php

sudo php /var/www/html/index.php --configure \
  --central-url=https://monitor.example.com \
  --node-id=ae-dxb-app-01 \
  --group-name=Production \
  --sample-interval=3

sudo php /var/www/html/index.php --install-agent
```

The installer detects systemd or OpenRC, creates `linxi-monitor-agent`, enables it at boot, and starts it immediately.

The central URL may point to a site root or directly to a PHP path:

```text
https://monitor.example.com
https://monitor.example.com/index.php
http://192.168.1.20/monitor.php
```

An empty node ID uses the machine hostname. The sample interval is restricted to 2-30 seconds.

## CLI reference

```bash
# Update embedded node settings
sudo php index.php --configure \
  --central-url=https://monitor.example.com \
  --node-id=my-node \
  --group-name=MyGroup \
  --sample-interval=3

# Install or update the background Agent
sudo php index.php --install-agent

# Run the Agent in the foreground for diagnosis
sudo -u www-data php index.php --agent
```

Configuration is embedded into the `MONITOR_EMBEDDED_SETTINGS` block inside the PHP file. Running `--configure` safely replaces only that block.

## Recommended Nginx configuration

```nginx
root /var/www/html;
index index.php;

location / {
    try_files $uri /index.php?$query_string;
}

location = /index.php {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /var/www/html/index.php;
    fastcgi_param SCRIPT_NAME /index.php;
    fastcgi_param PHP_SELF /index.php;
    fastcgi_param HTTPS $https;
    fastcgi_pass unix:/run/php/php8.3-fpm.sock;

    fastcgi_buffering off;
    fastcgi_read_timeout 3600s;
}

location ~ \.php$ {
    return 404;
}
```

Replace the PHP-FPM socket with the version installed on the server. Disabling FastCGI buffering is important for Server-Sent Events.

## File ownership and browser configuration

The recommended `root:www-data 0640` ownership lets PHP-FPM and the Agent read the file but prevents web requests from rewriting it. With these permissions, update embedded settings through `sudo php index.php --configure`.

The dashboard also contains a browser settings form for installations that intentionally make the file writable by the PHP user. CLI configuration is safer for Internet-reachable deployments.

## Data lifecycle

The project intentionally has no persistent database:

- Reporting nodes disappear from the overview after three minutes without a report.
- Shared node state and login sessions are cleared by a reboot or removal of the SysV shared-memory segment.
- The Agent automatically reconnects and repopulates the central overview.
- Historical charts exist only in the current browser session.

This design keeps the monitor small and disposable, but it is not intended for long-term metrics retention or audit logging.

## Troubleshooting

### The central overview does not appear

The page becomes a central overview after it receives a report from another node. Check the Agent service and ensure the connection key matches.

```bash
sudo systemctl status linxi-monitor-agent
sudo journalctl -u linxi-monitor-agent -n 100 --no-pager
```

### Live data disconnects

Confirm that FastCGI buffering is disabled and the read timeout is long enough. Also verify that PHP-FPM has enough workers for the number of simultaneously open dashboards.

### GPU information is unavailable

Install the appropriate vendor utility and make sure the PHP/Agent user can execute it. GPU monitoring is optional and does not affect CPU, memory, disk, or network telemetry.

### Embedded settings cannot be saved

Use the CLI command with `sudo`. A root-owned production file is intentionally not writable by PHP-FPM.

## External browser assets

The current interface loads fonts, icons, and Chart.js from public CDNs. Servers used on isolated networks must either allow those requests or replace the external assets with locally hosted equivalents.
