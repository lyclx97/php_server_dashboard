# PHP Server Dashboard

A lightweight, single-file PHP application for real-time Linux server monitoring. This tool provides a comprehensive dashboard to visualize system performance directly in your browser without the need for complex agents or external dependencies.

## 🚀 Features

- **Real-time Monitoring**: Powered by Server-Sent Events (SSE) for low-latency updates.
- **CPU Insights**: Total usage, per-core load, temperature, and model info.
- **Memory & Swap**: Detailed visualization of RAM and Swap usage.
- **Storage**: Disk space capacity and real-time Disk I/O (Read/Write speeds).
- **Networking**: Bandwidth monitoring (Upload/Download) and interface IP details.
- **GPU Support**: Auto-detects Intel and NVIDIA GPUs (requires `intel_gpu_top`, `xpu-smi`, or `nvidia-smi`).
- **Process Management**: View top 10 processes sorted by CPU usage.
- **System Info**: OS distribution, kernel version, uptime, and load averages.
- **Modern UI**: Dark-themed, responsive dashboard built with Chart.js and Font Awesome.

## 📋 Requirements

- **OS**: Linux (Targeted for `/proc` filesystem and standard CLI tools).
- **Web Server**: Apache, Nginx, or any PHP-capable server.
- **PHP**: 7.4 or higher.
- **Permissions**: The PHP user needs read access to `/proc` and `/sys`, and permission to execute basic commands like `ps`, `df`, and `ip`.

## ⚙️ Installation

1. Upload `index.php` to your web server's public directory.
2. Access the file via your browser (e.g., `http://your-server-ip/index.php`).

## 🔒 Password Protection

The dashboard is protected by a simple password layer to prevent unauthorized access.

### How to Change the Password

1. Open `index.php` in a text editor.
2. Locate the following line near the top of the file:
   ```php
   $PROTECTED_PASSWORD = "admin888"; // CHANGE THIS PASSWORD
   ```
3. Replace `"admin888"` with your desired secure password.
4. Save the file.

## 🛠️ Troubleshooting

- **No Data?**: Ensure your server is running Linux. This script relies heavily on the `/proc` filesystem.
- **SSE Connection Lost**: Check if your web server (like Nginx) has buffering enabled. The script attempts to disable it with `X-Accel-Buffering: no`, but some configurations might require manual adjustment.
- **GPU Stats Missing**: Ensure the necessary drivers and monitoring tools (`nvidia-smi`, `intel_gpu_top`, etc.) are installed and accessible by the PHP user.

### Recommended Nginx + PHP-FPM Settings (for stable SSE)

Use these settings to reduce random SSE disconnects and avoid frequent re-login caused by dropped long connections.

#### Nginx (location for `index.php`)

```nginx
location = /index.php {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root/index.php;
    fastcgi_pass unix:/run/php/php8.5-fpm.sock;

    # SSE stability
    fastcgi_buffering off;
    fastcgi_request_buffering off;
    gzip off;

    # Long-lived stream
    fastcgi_read_timeout 1h;
    fastcgi_send_timeout 1h;
    send_timeout 1h;
}
```

#### Nginx (global / server level)

```nginx
proxy_read_timeout 1h;
proxy_send_timeout 1h;
keepalive_timeout 75s;
```

#### PHP-FPM (`php.ini` / pool settings)

```ini
max_execution_time = 0
output_buffering = Off
zlib.output_compression = Off
session.gc_maxlifetime = 43200
```

```ini
; in php-fpm pool (www.conf)
request_terminate_timeout = 0
```

After updating configs, reload services:

```bash
sudo systemctl reload nginx
sudo systemctl reload php8.5-fpm
```

## 📄 License

This project is open-source. Feel free to modify and distribute as needed.
