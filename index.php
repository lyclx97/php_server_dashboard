<?php
/**
 * Server Resource Monitor - Single-file Linux deployment
 *
 * Requirements:
 *   - Nginx or Apache with PHP-FPM/CGI
 *   - PHP extensions: sysvshm, sysvsem and curl
 *   - No Docker, database, application config or runtime data files are required
 *
 * Ubuntu/Debian example (systemd, default site):
 *   sudo install -o root -g www-data -m 0640 index.php /var/www/html/index.php
 *   sudo php /var/www/html/index.php --configure \
 *     --central-url=https://monitor.example.com --node-id= --sample-interval=3
 *   sudo php /var/www/html/index.php --install-agent
 *
 * Alpine example (OpenRC, named monitor page):
 *   doas install -o root -g nobody -m 0640 monitor.php /var/www/default/monitor.php
 *   doas php83 /var/www/default/monitor.php --configure \
 *     --central-url=https://monitor.example.com --node-id= --sample-interval=3
 *   doas php83 /var/www/default/monitor.php --install-agent
 *
 * The --install-agent command automatically installs or updates the appropriate
 * systemd/OpenRC service and starts the Agent. Use --agent to run it in the
 * foreground. central-url may be a site root or a PHP path, for example:
 *   https://monitor.example.com
 *   http://192.168.1.20/monitor.php
 *
 * An empty node-id uses the machine hostname. Configuration is embedded in this
 * PHP file. Node state, detail leases, Agent status and login sessions live only
 * in SysV shared memory and may be rebuilt after a reboot.
 */

// Replace both placeholders before deployment. Every reporting node connected
// to the same central dashboard must currently use the same connection key.
$PROTECTED_PASSWORD = 'CHANGE_THIS_DASHBOARD_PASSWORD';
$MONITOR_CONNECTION_KEY = 'CHANGE_THIS_MONITOR_CONNECTION_KEY';
$monitorCredentialsConfigured = !str_starts_with($PROTECTED_PASSWORD, 'CHANGE_THIS_')
    && !str_starts_with($MONITOR_CONNECTION_KEY, 'CHANGE_THIS_');

/* MONITOR_EMBEDDED_SETTINGS
{"node_id":"","central_url":"","group_name":"","sample_interval":3}
MONITOR_EMBEDDED_SETTINGS_END */

// --- Distributed monitor configuration and transport ---
function monitorSharedKey(): int {
    static $key = null;
    if ($key === null) {
        $path = realpath(__FILE__) ?: __FILE__;
        $key = 0x10000000 + hexdec(substr(hash('sha256', $path), 0, 7));
    }
    return $key;
}

function monitorSharedState(array $state): array {
    return [
        'nodes' => is_array($state['nodes'] ?? null) ? $state['nodes'] : [],
        'subscriptions' => is_array($state['subscriptions'] ?? null) ? $state['subscriptions'] : [],
        'agent_status' => is_array($state['agent_status'] ?? null) ? $state['agent_status'] : [],
        'sessions' => is_array($state['sessions'] ?? null) ? $state['sessions'] : [],
    ];
}

function monitorSharedMutate(callable $mutator): mixed {
    if (!function_exists('shm_attach') || !function_exists('sem_get')) {
        throw new RuntimeException('The SysV shared memory extensions are unavailable.');
    }
    $key = monitorSharedKey();
    $semaphore = @sem_get($key, 1, 0660, true);
    if ($semaphore === false || !@sem_acquire($semaphore)) {
        throw new RuntimeException('Unable to lock shared monitor state.');
    }
    $memory = null;
    try {
        $memory = @shm_attach($key, 32 * 1024 * 1024, 0660);
        if ($memory === false) throw new RuntimeException('Unable to attach shared monitor state.');
        $state = shm_has_var($memory, 1) ? monitorSharedState((array)@shm_get_var($memory, 1)) : monitorSharedState([]);
        $result = $mutator($state);
        if (!@shm_put_var($memory, 1, monitorSharedState($state))) {
            throw new RuntimeException('Unable to update shared monitor state.');
        }
        return $result;
    } finally {
        if ($memory !== null && $memory !== false) @shm_detach($memory);
        @sem_release($semaphore);
    }
}

function monitorSharedRead(): array {
    try {
        return monitorSharedMutate(static fn(array &$state): array => $state);
    } catch (Throwable) {
        return monitorSharedState([]);
    }
}

function monitorSetAgentStatus(array $status): void {
    try {
        monitorSharedMutate(static function(array &$state) use ($status): void {
            $state['agent_status'] = $status;
        });
    } catch (Throwable) {
        // A transient shared-memory failure must not stop the reporting loop.
    }
}

function monitorUseSharedSessions(): void {
    session_set_save_handler(new class implements SessionHandlerInterface {
        public function open(string $path, string $name): bool { return true; }
        public function close(): bool { return true; }

        public function read(string $id): string|false {
            $session = monitorSharedRead()['sessions'][$id] ?? null;
            if (!is_array($session)) return '';
            if (time() - (int)($session['updated_at'] ?? 0) > (int)ini_get('session.gc_maxlifetime')) return '';
            return (string)($session['data'] ?? '');
        }

        public function write(string $id, string $data): bool {
            try {
                monitorSharedMutate(static function(array &$state) use ($id, $data): void {
                    $state['sessions'][$id] = ['data' => $data, 'updated_at' => time()];
                });
                return true;
            } catch (Throwable) {
                return false;
            }
        }

        public function destroy(string $id): bool {
            try {
                monitorSharedMutate(static function(array &$state) use ($id): void {
                    unset($state['sessions'][$id]);
                });
                return true;
            } catch (Throwable) {
                return false;
            }
        }

        public function gc(int $max_lifetime): int|false {
            try {
                return monitorSharedMutate(static function(array &$state) use ($max_lifetime): int {
                    $removed = 0;
                    foreach ($state['sessions'] as $id => $session) {
                        if (time() - (int)($session['updated_at'] ?? 0) > $max_lifetime) {
                            unset($state['sessions'][$id]);
                            $removed++;
                        }
                    }
                    return $removed;
                });
            } catch (Throwable) {
                return false;
            }
        }
    }, true);
}

function monitorInstallAgentService(string $scriptPath): never {
    if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
        fwrite(STDERR, "Run this command with sudo.\n");
        exit(1);
    }
    $scriptPath = realpath($scriptPath) ?: $scriptPath;
    $quote = static fn(string $value): string => '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
    $serviceUser = 'www-data';
    $serviceGroup = 'www-data';
    foreach (glob('/etc/php*/php-fpm.d/www.conf') ?: [] as $poolPath) {
        $pool = (string)@file_get_contents($poolPath);
        if (preg_match('/^\s*user\s*=\s*([^;\s]+)/m', $pool, $match)) $serviceUser = $match[1];
        if (preg_match('/^\s*group\s*=\s*([^;\s]+)/m', $pool, $match)) $serviceGroup = $match[1];
        break;
    }
    if (function_exists('posix_getpwnam') && posix_getpwnam($serviceUser) === false) {
        $serviceUser = posix_getpwnam('nginx') !== false ? 'nginx' : 'nobody';
    }
    if (function_exists('posix_getgrnam') && posix_getgrnam($serviceGroup) === false) $serviceGroup = $serviceUser;

    if (is_executable('/sbin/openrc-run') && is_executable('/sbin/rc-service')) {
        $servicePath = '/etc/init.d/linxi-monitor-agent';
        $init = "#!/sbin/openrc-run\n"
            . "description=\"Linxi distributed monitor agent\"\n"
            . "command=" . $quote(PHP_BINARY) . "\n"
            . "command_args=" . $quote($quote($scriptPath) . ' --agent') . "\n"
            . "command_user=" . $quote($serviceUser . ':' . $serviceGroup) . "\n"
            . "supervisor=\"supervise-daemon\"\n"
            . "respawn_delay=5\n"
            . "respawn_max=0\n\n"
            . "depend() {\n"
            . "    need net\n"
            . "    after nginx php-fpm83\n"
            . "}\n";
        if (file_put_contents($servicePath, $init, LOCK_EX) === false) {
            fwrite(STDERR, "Unable to write $servicePath.\n");
            exit(1);
        }
        chmod($servicePath, 0755);
        system('rc-update add linxi-monitor-agent default', $updateStatus);
        system('rc-service linxi-monitor-agent restart', $startStatus);
        if ($updateStatus !== 0 || $startStatus !== 0) exit(1);
        echo "Managed OpenRC Agent service installed and started.\n";
        exit;
    }

    $unit = "[Unit]\n"
        . "Description=Linxi distributed monitor agent\n"
        . "After=network-online.target nginx.service php8.5-fpm.service\n"
        . "Wants=network-online.target\n\n"
        . "[Service]\n"
        . "Type=simple\n"
        . "User=" . $serviceUser . "\n"
        . "Group=" . $serviceGroup . "\n"
        . "ExecStart=" . $quote(PHP_BINARY) . ' ' . $quote($scriptPath) . " --agent\n"
        . "Restart=always\n"
        . "RestartSec=5\n"
        . "NoNewPrivileges=true\n"
        . "PrivateTmp=true\n"
        . "ProtectSystem=full\n\n"
        . "[Install]\n"
        . "WantedBy=multi-user.target\n";
    $servicePath = '/etc/systemd/system/linxi-monitor-agent.service';
    if (file_put_contents($servicePath, $unit, LOCK_EX) === false) {
        fwrite(STDERR, "Unable to write $servicePath.\n");
        exit(1);
    }
    chmod($servicePath, 0644);
    system('systemctl daemon-reload', $reloadStatus);
    system('systemctl enable --now linxi-monitor-agent.service', $enableStatus);
    if ($reloadStatus !== 0 || $enableStatus !== 0) exit(1);
    echo "Managed Agent service installed and started.\n";
    exit;
}

function monitorConfig(string $scriptPath): array {
    $defaults = [
        'node_id' => php_uname('n') ?: 'linux-node',
        'central_url' => '',
        'group_name' => '',
        'sample_interval' => 3,
    ];
    $handle = @fopen($scriptPath, 'rb');
    if (!$handle) return $defaults;
    @flock($handle, LOCK_SH);
    $source = stream_get_contents($handle);
    @flock($handle, LOCK_UN);
    fclose($handle);
    if (!preg_match('#/\* MONITOR_EMBEDDED_SETTINGS\R(.*?)\RMONITOR_EMBEDDED_SETTINGS_END \*/#s', (string)$source, $match)) return $defaults;
    $stored = json_decode(trim($match[1]), true);
    if (!is_array($stored)) return $defaults;
    $config = array_replace($defaults, $stored);
    if (trim((string)$config['node_id']) === '') $config['node_id'] = $defaults['node_id'];
    $config['group_name'] = monitorNormalizeGroupName($config['group_name'] ?? '');
    $config['sample_interval'] = max(2, min(30, (int)$config['sample_interval']));
    return $config;
}

function monitorNormalizeGroupName(mixed $value): string {
    if (!is_string($value)) return '';
    $name = trim((string)(preg_replace('/[\x00-\x1F\x7F]/u', '', $value) ?? ''));
    return function_exists('mb_substr') ? mb_substr($name, 0, 80, 'UTF-8') : substr($name, 0, 160);
}

function monitorWriteConfig(string $scriptPath, array $config): bool {
    $handle = @fopen($scriptPath, 'c+');
    if (!$handle || !@flock($handle, LOCK_EX)) {
        if ($handle) fclose($handle);
        return false;
    }
    rewind($handle);
    $source = stream_get_contents($handle);
    $stored = [
        'node_id' => (string)$config['node_id'],
        'central_url' => (string)$config['central_url'],
        'group_name' => monitorNormalizeGroupName($config['group_name'] ?? ''),
        'sample_interval' => max(2, min(30, (int)$config['sample_interval'])),
    ];
    $replacement = "/* MONITOR_EMBEDDED_SETTINGS\n" . json_encode($stored, JSON_UNESCAPED_SLASHES) . "\nMONITOR_EMBEDDED_SETTINGS_END */";
    $updated = preg_replace('#/\* MONITOR_EMBEDDED_SETTINGS\R.*?\RMONITOR_EMBEDDED_SETTINGS_END \*/#s', $replacement, (string)$source, 1, $count);
    $ok = $count === 1 && is_string($updated);
    if ($ok) {
        rewind($handle);
        $ok = ftruncate($handle, 0) && fwrite($handle, $updated) === strlen($updated) && fflush($handle);
    }
    @flock($handle, LOCK_UN);
    fclose($handle);
    return $ok;
}

function monitorJsonResponse(array $payload, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

function monitorReadCpuCounters(): array {
    $line = strtok((string)@file_get_contents('/proc/stat'), "\n");
    $parts = preg_split('/\s+/', trim((string)$line));
    if (($parts[0] ?? '') !== 'cpu') return ['idle' => 0, 'total' => 0];
    $values = array_map('intval', array_slice($parts, 1));
    $idle = ($values[3] ?? 0) + ($values[4] ?? 0);
    return ['idle' => $idle, 'total' => array_sum($values)];
}

function monitorReadNetworkCounters(): array {
    $rx = 0.0;
    $tx = 0.0;
    foreach (explode("\n", (string)@file_get_contents('/proc/net/dev')) as $line) {
        if (!str_contains($line, ':')) continue;
        [$name, $numbers] = array_map('trim', explode(':', $line, 2));
        if ($name === 'lo') continue;
        $parts = preg_split('/\s+/', $numbers);
        $rx += (float)($parts[0] ?? 0);
        $tx += (float)($parts[8] ?? 0);
    }
    return ['rx' => $rx, 'tx' => $tx];
}

function monitorReadMemory(): array {
    $values = [];
    foreach (explode("\n", (string)@file_get_contents('/proc/meminfo')) as $line) {
        if (preg_match('/^([A-Za-z_()]+):\s+(\d+)/', $line, $m)) $values[$m[1]] = (float)$m[2] * 1024;
    }
    $total = $values['MemTotal'] ?? 0;
    $available = $values['MemAvailable'] ?? (($values['MemFree'] ?? 0) + ($values['Buffers'] ?? 0) + ($values['Cached'] ?? 0));
    $swapTotal = $values['SwapTotal'] ?? 0;
    $swapFree = $values['SwapFree'] ?? 0;
    return [
        'used' => max(0, $total - $available),
        'total' => $total,
        'percentage' => $total > 0 ? (($total - $available) / $total * 100) : 0,
        'swap_used' => max(0, $swapTotal - $swapFree),
        'swap_total' => $swapTotal,
    ];
}

function monitorReadTemperature(): ?float {
    $temps = [];
    foreach (glob('/sys/class/thermal/thermal_zone*/temp') ?: [] as $path) {
        $value = (float)trim((string)@file_get_contents($path));
        if ($value > 1000) $value /= 1000;
        if ($value > 0 && $value < 150) $temps[] = $value;
    }
    return $temps ? max($temps) : null;
}

function monitorReadGpu(): array {
    $out = @shell_exec('nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits 2>/dev/null');
    if (!$out) return ['available' => false];
    $devices = [];
    foreach (explode("\n", trim($out)) as $line) {
        $p = array_map('trim', str_getcsv($line));
        if (count($p) < 6) continue;
        $devices[] = [
            'index' => (int)$p[0], 'name' => $p[1], 'usage' => (float)$p[2],
            'memory_used' => (float)$p[3] * 1048576, 'memory_total' => (float)$p[4] * 1048576,
            'temperature' => (float)$p[5],
        ];
    }
    if (!$devices) return ['available' => false];
    return [
        'available' => true,
        'usage' => max(array_column($devices, 'usage')),
        'memory_used' => array_sum(array_column($devices, 'memory_used')),
        'memory_total' => array_sum(array_column($devices, 'memory_total')),
        'temperature' => max(array_column($devices, 'temperature')),
        'devices' => $devices,
    ];
}

function monitorStaticInfo(): array {
    $distro = 'Linux';
    $osRelease = (string)@file_get_contents('/etc/os-release');
    if (preg_match('/^PRETTY_NAME=["\']?([^"\'\n]+)["\']?/m', $osRelease, $m)) $distro = trim($m[1]);
    $cpuModel = 'Unknown CPU';
    $lscpu = (string)@shell_exec('lscpu 2>/dev/null');
    if (preg_match('/^(?:BIOS )?Model name:\s*(.+)$/mi', $lscpu, $m)) $cpuModel = trim($m[1]);
    return [
        'hostname' => php_uname('n'), 'os' => $distro, 'kernel' => php_uname('r'),
        'architecture' => php_uname('m'), 'cpu_model' => $cpuModel,
        'cpu_cores' => (int)trim((string)@shell_exec('getconf _NPROCESSORS_ONLN 2>/dev/null')),
    ];
}

function monitorCollectSummary(array &$state): array {
    $now = microtime(true);
    $cpu = monitorReadCpuCounters();
    $network = monitorReadNetworkCounters();
    $elapsed = max(0.001, $now - ($state['time'] ?? $now));
    $totalDelta = $cpu['total'] - ($state['cpu']['total'] ?? $cpu['total']);
    $idleDelta = $cpu['idle'] - ($state['cpu']['idle'] ?? $cpu['idle']);
    $cpuUsage = $totalDelta > 0 ? max(0, min(100, (1 - $idleDelta / $totalDelta) * 100)) : 0;
    $rxSpeed = max(0, ($network['rx'] - ($state['network']['rx'] ?? $network['rx'])) / $elapsed);
    $txSpeed = max(0, ($network['tx'] - ($state['network']['tx'] ?? $network['tx'])) / $elapsed);
    $state = ['time' => $now, 'cpu' => $cpu, 'network' => $network, 'primed' => $state['primed'] ?? false];
    $memory = monitorReadMemory();
    $diskTotal = (float)@disk_total_space('/');
    $diskFree = (float)@disk_free_space('/');
    $loads = sys_getloadavg() ?: [0, 0, 0];
    $uptime = (float)strtok((string)@file_get_contents('/proc/uptime'), ' ');
    return [
        'cpu' => ['usage' => round($cpuUsage, 1), 'temperature' => monitorReadTemperature()],
        'memory' => $memory,
        'disk' => ['used' => max(0, $diskTotal - $diskFree), 'total' => $diskTotal, 'percentage' => $diskTotal > 0 ? (($diskTotal - $diskFree) / $diskTotal * 100) : 0],
        'network' => ['rx_speed' => $rxSpeed, 'tx_speed' => $txSpeed, 'rx_total' => $network['rx'], 'tx_total' => $network['tx']],
        'load' => array_values(array_map(fn($v) => round((float)$v, 2), array_slice($loads, 0, 3))),
        'uptime' => $uptime,
        'gpu' => monitorReadGpu(),
    ];
}

function monitorPostReport(string $url, string $nodeId, string $secret, array $payload): array {
    $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
    $timestamp = (string)time();
    $signature = hash_hmac('sha256', $timestamp . "\n" . $nodeId . "\n" . $body, $secret);
    $baseUrl = rtrim($url, '/');
    $urlPath = (string)(parse_url($baseUrl, PHP_URL_PATH) ?: '');
    $endpoint = $baseUrl . ($urlPath !== '' && $urlPath !== '/' ? '?' : '/?') . 'monitor_api=ingest';
    if (function_exists('curl_init')) {
        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_TIMEOUT => 15,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Monitor-Node: ' . $nodeId, 'X-Monitor-Timestamp: ' . $timestamp, 'X-Monitor-Signature: ' . $signature],
        ]);
        $response = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        $decoded = is_string($response) ? json_decode($response, true) : null;
        return [
            'ok' => $response !== false && $status >= 200 && $status < 300,
            'status' => $status, 'error' => $error ?: null,
            'detail_requested' => !empty($decoded['detail_requested']),
        ];
    }
    $context = stream_context_create(['http' => [
        'method' => 'POST', 'timeout' => 15, 'ignore_errors' => true, 'content' => $body,
        'header' => "Content-Type: application/json\r\nX-Monitor-Node: $nodeId\r\nX-Monitor-Timestamp: $timestamp\r\nX-Monitor-Signature: $signature\r\n",
    ]]);
    $response = @file_get_contents($endpoint, false, $context);
    $statusLine = $http_response_header[0] ?? '';
    preg_match('/\s(\d{3})\s/', $statusLine, $m);
    $status = (int)($m[1] ?? 0);
    $decoded = is_string($response) ? json_decode($response, true) : null;
    return [
        'ok' => $response !== false && $status >= 200 && $status < 300,
        'status' => $status, 'error' => $response === false ? 'Connection failed' : null,
        'detail_requested' => !empty($decoded['detail_requested']),
    ];
}

function monitorFetchLocalDetail(): ?array {
    $context = stream_context_create(['http' => ['timeout' => 15, 'ignore_errors' => true]]);
    $localPath = '/' . rawurlencode(basename(__FILE__));
    $stream = @fopen('http://127.0.0.1' . $localPath . '?monitor_agent_stream=1', 'r', false, $context);
    if (!$stream) return null;
    stream_set_timeout($stream, 15);
    $detail = null;
    while (!feof($stream)) {
        $line = fgets($stream);
        if ($line === false) break;
        if (str_starts_with($line, 'data: ')) {
            $decoded = json_decode(substr($line, 6), true);
            if (is_array($decoded)) $detail = $decoded;
            break;
        }
    }
    fclose($stream);
    return $detail;
}

function monitorRunAgent(string $scriptPath, string $connectionKey): never {
    @set_time_limit(0);
    $collectorState = [];
    $staticInfo = monitorStaticInfo();
    $failureCount = 0;
    $lastStatic = 0;
    while (true) {
        $config = monitorConfig($scriptPath);
        $url = trim((string)$config['central_url']);
        $nodeId = preg_replace('/[^A-Za-z0-9._-]/', '-', (string)$config['node_id']);
        if ($url === '' || $nodeId === '') {
            monitorSetAgentStatus(['ok' => false, 'updated_at' => time(), 'message' => 'Central connection is not configured']);
            sleep(10);
            continue;
        }
        $metrics = monitorCollectSummary($collectorState);
        if (empty($collectorState['primed'])) {
            $collectorState['primed'] = true;
            sleep(1);
            continue;
        }
        $payload = [
            'schema' => 1,
            'sent_at' => time(),
            'group_name' => monitorNormalizeGroupName($config['group_name'] ?? ''),
            'metrics' => $metrics,
        ];
        if (time() - $lastStatic >= 3600) $payload['system'] = $staticInfo;
        $result = monitorPostReport($url, $nodeId, $connectionKey, $payload);
        if ($result['ok']) {
            if (!empty($result['detail_requested'])) {
                $detail = monitorFetchLocalDetail();
                if ($detail !== null) {
                    $payload['sent_at'] = time();
                    $payload['detail'] = $detail;
                    $detailResult = monitorPostReport($url, $nodeId, $connectionKey, $payload);
                    if (!$detailResult['ok']) $result = $detailResult;
                }
            }
        }
        if ($result['ok']) {
            $failureCount = 0;
            if (isset($payload['system'])) $lastStatic = time();
            monitorSetAgentStatus(['ok' => true, 'updated_at' => time(), 'status' => $result['status'], 'message' => 'Connected']);
            sleep(max(2, min(30, (int)$config['sample_interval'])));
        } else {
            $failureCount++;
            monitorSetAgentStatus(['ok' => false, 'updated_at' => time(), 'status' => $result['status'], 'message' => $result['error'] ?: ('HTTP ' . $result['status'])]);
            sleep(min(60, max(3, 2 ** min(6, $failureCount))));
        }
    }
}

$monitorConfig = monitorConfig(__FILE__);

function monitorActiveNodes(): array {
    try {
        return monitorSharedMutate(static function(array &$state): array {
            $now = time();
            foreach ($state['nodes'] as $nodeId => $node) {
                $receivedAt = is_array($node) ? (int)($node['received_at'] ?? 0) : 0;
                if ($receivedAt <= 0 || $now - $receivedAt >= 180) {
                    unset($state['nodes'][$nodeId], $state['subscriptions'][$nodeId]);
                }
            }
            return $state['nodes'];
        });
    } catch (Throwable) {
        return [];
    }
}

function monitorListNodes(): array {
    $nodes = [];
    foreach (monitorActiveNodes() as $node) {
        if (!$node || empty($node['node_id']) || !is_array($node['metrics'] ?? null)) continue;
        $age = max(0, time() - (int)($node['received_at'] ?? 0));
        $node['age_seconds'] = $age;
        $node['status'] = $age <= 12 ? 'online' : ($age <= 60 ? 'degraded' : 'offline');
        $nodes[] = $node;
    }
    usort($nodes, function(array $a, array $b): int {
        $rank = ['online' => 0, 'degraded' => 1, 'offline' => 2];
        return ($rank[$a['status']] <=> $rank[$b['status']]) ?: strnatcasecmp($a['node_id'], $b['node_id']);
    });
    return $nodes;
}

function monitorOverviewNodes(array &$localCollectorState, array $config, string $hostname, ?array $localSystem = null): array {
    $localNodeId = preg_replace('/[^A-Za-z0-9._-]/', '-', trim((string)($config['node_id'] ?? '')));
    if ($localNodeId === '') $localNodeId = preg_replace('/[^A-Za-z0-9._-]/', '-', $hostname) ?: 'local-server';

    // The central server is sampled in-process. It must not run an Agent that
    // reports back to itself, which would create a duplicate node and a loop.
    $nodes = array_values(array_filter(
        monitorListNodes(),
        static fn(array $node): bool => (string)($node['node_id'] ?? '') !== $localNodeId
    ));
    array_unshift($nodes, [
        'node_id' => $localNodeId,
        'received_at' => time(),
        'sent_at' => time(),
        'age_seconds' => 0,
        'status' => 'online',
        'is_local' => true,
        'group_name' => monitorNormalizeGroupName($config['group_name'] ?? ''),
        'system' => $localSystem ?? monitorStaticInfo(),
        'metrics' => monitorCollectSummary($localCollectorState),
    ]);
    return $nodes;
}

function monitorDetectCentral(string $localNodeId): bool {
    foreach (monitorActiveNodes() as $node) {
        if (!empty($node['node_id']) && $node['node_id'] !== $localNodeId) return true;
    }
    return false;
}

if (PHP_SAPI === 'cli' && in_array('--configure', $argv ?? [], true)) {
    $newConfig = $monitorConfig;
    foreach ($argv as $argument) {
        if (str_starts_with($argument, '--central-url=')) $newConfig['central_url'] = rtrim(substr($argument, 14), '/');
        if (str_starts_with($argument, '--node-id=')) $newConfig['node_id'] = preg_replace('/[^A-Za-z0-9._-]/', '-', substr($argument, 10));
        if (str_starts_with($argument, '--group-name=')) $newConfig['group_name'] = monitorNormalizeGroupName(substr($argument, 13));
        if (str_starts_with($argument, '--sample-interval=')) $newConfig['sample_interval'] = max(2, min(30, (int)substr($argument, 18)));
    }
    if (!monitorWriteConfig(__FILE__, $newConfig)) {
        fwrite(STDERR, "Unable to update embedded settings.\n");
        exit(1);
    }
    echo "Embedded settings updated.\n";
    exit;
}

if (PHP_SAPI === 'cli' && in_array('--install-agent', $argv ?? [], true)) {
    if (!$monitorCredentialsConfigured) {
        fwrite(STDERR, "Set the dashboard password and monitor connection key before installing the Agent.\n");
        exit(1);
    }
    monitorInstallAgentService(__FILE__);
}

if (PHP_SAPI === 'cli' && in_array('--agent', $argv ?? [], true)) {
    if (!$monitorCredentialsConfigured) {
        fwrite(STDERR, "Set the dashboard password and monitor connection key before starting the Agent.\n");
        exit(1);
    }
    monitorRunAgent(__FILE__, $MONITOR_CONNECTION_KEY);
}

// Agent ingestion is authenticated independently and intentionally bypasses browser sessions.
if (($_GET['monitor_api'] ?? '') === 'ingest') {
    if (!$monitorCredentialsConfigured) monitorJsonResponse(['ok' => false, 'error' => 'Monitor credentials are not configured'], 503);
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') monitorJsonResponse(['ok' => false, 'error' => 'Not found'], 404);
    $body = (string)file_get_contents('php://input');
    if ($body === '' || strlen($body) > 131072) monitorJsonResponse(['ok' => false, 'error' => 'Invalid payload'], 400);
    $nodeId = (string)($_SERVER['HTTP_X_MONITOR_NODE'] ?? '');
    $timestamp = (string)($_SERVER['HTTP_X_MONITOR_TIMESTAMP'] ?? '');
    $signature = (string)($_SERVER['HTTP_X_MONITOR_SIGNATURE'] ?? '');
    if (!preg_match('/^[A-Za-z0-9._-]{1,80}$/', $nodeId) || !ctype_digit($timestamp) || abs(time() - (int)$timestamp) > 300) monitorJsonResponse(['ok' => false, 'error' => 'Invalid authentication'], 401);
    $expected = hash_hmac('sha256', $timestamp . "\n" . $nodeId . "\n" . $body, $MONITOR_CONNECTION_KEY);
    if ($signature === '' || !hash_equals($expected, $signature)) monitorJsonResponse(['ok' => false, 'error' => 'Invalid authentication'], 401);
    $report = json_decode($body, true);
    if (!is_array($report) || !isset($report['metrics']) || !is_array($report['metrics'])) monitorJsonResponse(['ok' => false, 'error' => 'Invalid report'], 422);
    try {
        $detailRequested = monitorSharedMutate(static function(array &$state) use ($nodeId, $report): bool {
            $previous = is_array($state['nodes'][$nodeId] ?? null) ? $state['nodes'][$nodeId] : [];
            $state['nodes'][$nodeId] = [
                'node_id' => $nodeId,
                'received_at' => time(),
                'sent_at' => (int)($report['sent_at'] ?? time()),
                'group_name' => monitorNormalizeGroupName($report['group_name'] ?? ''),
                'system' => is_array($report['system'] ?? null) ? $report['system'] : ($previous['system'] ?? []),
                'metrics' => $report['metrics'],
                'detail' => is_array($report['detail'] ?? null) ? $report['detail'] : ($previous['detail'] ?? null),
                'detail_received_at' => is_array($report['detail'] ?? null) ? time() : (int)($previous['detail_received_at'] ?? 0),
            ];
            foreach ($state['subscriptions'] as $subscribedNode => $until) {
                if ((int)$until < time()) unset($state['subscriptions'][$subscribedNode]);
            }
            return (int)($state['subscriptions'][$nodeId] ?? 0) >= time();
        });
    } catch (Throwable) {
        monitorJsonResponse(['ok' => false, 'error' => 'Shared state unavailable'], 503);
    }
    $upstreamUrl = trim((string)($monitorConfig['central_url'] ?? ''));
    $upstreamHost = strtolower((string)(parse_url($upstreamUrl, PHP_URL_HOST) ?: ''));
    $requestHost = strtolower(preg_replace('/:\d+$/', '', (string)($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '')));
    if ($upstreamUrl !== '' && $upstreamHost !== '' && $upstreamHost !== $requestHost) {
        $relay = monitorPostReport($upstreamUrl, $nodeId, $MONITOR_CONNECTION_KEY, $report);
        if ($relay['ok'] && !empty($relay['detail_requested'])) $detailRequested = true;
    }
    monitorJsonResponse(['ok' => true, 'server_time' => time(), 'detail_requested' => $detailRequested]);
}

$monitorTrustedAgentStream = isset($_GET['monitor_agent_stream']) && in_array((string)($_SERVER['REMOTE_ADDR'] ?? ''), ['127.0.0.1', '::1'], true);
if ($monitorTrustedAgentStream) $_GET['stream'] = 1;

if (!$monitorTrustedAgentStream && !$monitorCredentialsConfigured) {
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo "Server Monitor is not configured. Set the dashboard password and monitor connection key in index.php before deployment.\n";
    exit;
}

// --- Password Protection ---
// Keep login session valid longer (12h) to avoid frequent re-login after reconnects.
$sessionLifetime = 43200;
ini_set('session.gc_maxlifetime', (string)$sessionLifetime);
monitorUseSharedSessions();
$cookieParams = session_get_cookie_params();
session_set_cookie_params([
    'lifetime' => $sessionLifetime,
    'path' => $cookieParams['path'] ?? '/',
    'domain' => $cookieParams['domain'] ?? '',
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'httponly' => $cookieParams['httponly'] ?? true,
    'samesite' => $cookieParams['samesite'] ?? 'Lax',
]);
session_start();

if (!$monitorTrustedAgentStream && !isset($_SESSION['authenticated'])) {
    if (isset($_POST['password']) && $_POST['password'] === $PROTECTED_PASSWORD) {
        session_regenerate_id(true);
        $_SESSION['authenticated'] = true;
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit;
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - Server Monitor</title>
        <style>
            body { font-family: 'Roboto', sans-serif; background-color: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
            .login-card { background: #1e1e1e; padding: 40px 30px; border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.6); border: 1px solid #333; width: 100%; max-width: 400px; text-align: center; }
            h2 { color: #4fc3f7; margin-bottom: 25px; font-weight: 500; letter-spacing: 0.5px; }
            input[type="password"] { width: 100%; padding: 14px; margin-bottom: 20px; border-radius: 6px; border: 1px solid #444; background: #2a2a2a; color: #fff; box-sizing: border-box; font-size: 16px; outline: none; transition: border-color 0.3s; }
            input[type="password"]:focus { border-color: #4fc3f7; }
            button { width: 100%; padding: 14px; border: none; border-radius: 6px; background: #4fc3f7; color: #000; font-weight: bold; cursor: pointer; transition: background 0.3s, transform 0.1s; font-size: 16px; }
            button:hover { background: #29b6f6; }
            button:active { transform: scale(0.98); }
            .error { color: #f44336; margin-bottom: 20px; font-size: 14px; background: rgba(244, 67, 54, 0.1); padding: 10px; border-radius: 4px; border: 1px solid rgba(244, 67, 54, 0.2); }
            
            @media (max-width: 480px) {
                .login-card { padding: 30px 20px; }
                h2 { font-size: 20px; }
            }
        </style>
    </head>
    <body>
        <div class="login-card">
            <h2>Server Monitor</h2>
            <?php if (isset($_POST['password'])): ?>
                <div class="error">Invalid Password</div>
            <?php endif; ?>
            <form method="post">
                <input type="password" name="password" placeholder="Enter Password" autofocus required>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 0);

// Hostname for display
$hostname = php_uname('n') ?: (function_exists('gethostname') ? gethostname() : '');
$monitorIsCentral = monitorDetectCentral((string)$monitorConfig['node_id']);

// --- Backend Logic ---

if (empty($_SESSION['monitor_csrf'])) $_SESSION['monitor_csrf'] = bin2hex(random_bytes(24));

if (isset($_POST['monitor_save_config'])) {
    if (!hash_equals((string)$_SESSION['monitor_csrf'], (string)($_POST['csrf'] ?? ''))) monitorJsonResponse(['ok' => false, 'error' => 'Invalid request'], 403);
    $centralUrl = trim((string)($_POST['central_url'] ?? ''));
    if ($centralUrl !== '' && !preg_match('#^https?://#i', $centralUrl)) $centralUrl = 'https://' . $centralUrl;
    $parts = $centralUrl !== '' ? parse_url($centralUrl) : [];
    if ($centralUrl !== '' && (!$parts || !in_array(strtolower((string)($parts['scheme'] ?? '')), ['http', 'https'], true) || empty($parts['host']) || isset($parts['user']) || isset($parts['pass']))) {
        $_SESSION['monitor_config_message'] = ['type' => 'error', 'text' => 'Enter a valid Central server domain or IP address.'];
    } else {
        $nodeId = preg_replace('/[^A-Za-z0-9._-]/', '-', trim((string)($_POST['node_id'] ?? $hostname)));
        $newConfig = $monitorConfig;
        $newConfig['node_id'] = substr($nodeId ?: $hostname, 0, 80);
        $newConfig['central_url'] = rtrim($centralUrl, '/');
        $newConfig['group_name'] = monitorNormalizeGroupName($_POST['group_name'] ?? '');
        $newConfig['sample_interval'] = max(2, min(30, (int)($_POST['sample_interval'] ?? 3)));
        if (monitorWriteConfig(__FILE__, $newConfig)) {
            $monitorConfig = $newConfig;
            $_SESSION['monitor_config_message'] = ['type' => 'success', 'text' => 'Central connection saved. The Agent service will apply it automatically.'];
        } else {
            $_SESSION['monitor_config_message'] = ['type' => 'error', 'text' => 'The configuration could not be saved.'];
        }
    }
    $redirect = strtok((string)$_SERVER['REQUEST_URI'], '?') ?: '/';
    header('Location: ' . $redirect);
    exit;
}

if (($_GET['monitor_api'] ?? '') === 'nodes') {
    if (!$monitorIsCentral) monitorJsonResponse(['ok' => false, 'error' => 'Not available'], 404);
    $localCollectorState = [];
    monitorJsonResponse(['ok' => true, 'server_time' => time(), 'nodes' => monitorOverviewNodes($localCollectorState, $monitorConfig, $hostname)]);
}

if (($_GET['monitor_api'] ?? '') === 'overview_stream') {
    if (!$monitorIsCentral) monitorJsonResponse(['ok' => false, 'error' => 'Not available'], 404);
    @set_time_limit(0);
    @ini_set('output_buffering', 'off');
    @ini_set('zlib.output_compression', '0');
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache, no-transform');
    header('X-Accel-Buffering: no');
    echo "retry: 3000\n\n";
    while (ob_get_level() > 0) @ob_end_flush();
    @ob_implicit_flush(true);
    session_write_close();
    $localCollectorState = [];
    $localSystem = monitorStaticInfo();
    while (!connection_aborted()) {
        echo 'data: ' . json_encode([
            'server_time' => time(),
            'nodes' => monitorOverviewNodes($localCollectorState, $monitorConfig, $hostname, $localSystem),
        ], JSON_UNESCAPED_SLASHES) . "\n\n";
        flush();
        sleep(3);
    }
    exit;
}

if (($_GET['monitor_api'] ?? '') === 'remote_stream') {
    if (!$monitorIsCentral) monitorJsonResponse(['ok' => false, 'error' => 'Not available'], 404);
    $nodeId = (string)($_GET['node'] ?? '');
    if (!preg_match('/^[A-Za-z0-9._-]{1,80}$/', $nodeId)) monitorJsonResponse(['ok' => false, 'error' => 'Invalid node'], 400);
    @set_time_limit(0);
    @ini_set('output_buffering', 'off');
    @ini_set('zlib.output_compression', '0');
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache, no-transform');
    header('X-Accel-Buffering: no');
    echo "retry: 3000\n\n";
    while (ob_get_level() > 0) @ob_end_flush();
    @ob_implicit_flush(true);
    session_write_close();
    while (!connection_aborted()) {
        try {
            $node = monitorSharedMutate(static function(array &$state) use ($nodeId): array {
                $state['subscriptions'][$nodeId] = time() + 15;
                return is_array($state['nodes'][$nodeId] ?? null) ? $state['nodes'][$nodeId] : [];
            });
        } catch (Throwable) {
            $node = [];
        }
        if (is_array($node['detail'] ?? null) && time() - (int)($node['detail_received_at'] ?? 0) <= 12) {
            echo 'data: ' . json_encode($node['detail'], JSON_UNESCAPED_SLASHES) . "\n\n";
        } else {
            echo ": waiting for Agent detail\n\n";
        }
        flush();
        sleep(1);
    }
    exit;
}

if (isset($_GET['stream'])) {
    // Make SSE stream long-lived and reduce server-side timeout disconnects.
    @set_time_limit(0);
    @ini_set('max_execution_time', '0');
    @ini_set('output_buffering', 'off');
    @ini_set('zlib.output_compression', '0');

    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache, no-transform');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no'); // Disable buffering for Nginx
    header('Content-Encoding: none');
    echo "retry: 3000\n\n";
    // Try to disable all PHP output buffering layers for low-latency SSE.
    while (ob_get_level() > 0) {
        @ob_end_flush();
    }
    @ob_implicit_flush(true);

    $read_cpu = function() {
        $data = @file_get_contents('/proc/stat');
        if (!$data) return [];
        $cpus = [];
        foreach (explode("\n", $data) as $line) {
            if (preg_match('/^cpu(\d*)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/', $line, $m)) {
                $name = $m[1] === '' ? 'total' : 'cpu' . $m[1];
                $cpus[$name] = [
                    'idle' => (int)$m[5] + (int)$m[6], // idle + iowait
                    'total' => (int)$m[2] + (int)$m[3] + (int)$m[4] + (int)$m[5] + (int)$m[6] + (int)$m[7] + (int)$m[8]
                ];
            }
        }
        return $cpus;
    };

    $read_net = function() {
        $data = @file_get_contents('/proc/net/dev');
        if (!$data) return [];
        $net = [];
        foreach (explode("\n", $data) as $line) {
            if (strpos($line, ':') === false) continue;
            $parts = preg_split('/[:\s]+/', trim($line));
            if (count($parts) < 10) continue;
            $net[$parts[0]] = ['rx' => (float)$parts[1], 'tx' => (float)$parts[9]];
        }
        return $net;
    };

    // Static system info
    $distro = 'Linux';
    if ($os_rel = @file_get_contents('/etc/os-release')) {
        if (preg_match('/PRETTY_NAME="([^"]+)"/', $os_rel, $m)) $distro = $m[1];
    }
    // --- Memory Speed Detection ---
    $memory_speed = null;
    $lshw_out = shell_exec('sudo lshw -short 2>/dev/null');
    if ($lshw_out) {
        if (preg_match('/(\d+)\s+MHz/', $lshw_out, $m)) $memory_speed = (int)$m[1];
    }
    
    // --- Improved CPU Model Detection ---
    $cpu_model = 'Unknown CPU';
    
    // Method 1: Try lscpu (Most reliable for OCI ARM / Ampere)
    $lscpu_out = shell_exec('lscpu 2>/dev/null');
    if ($lscpu_out) {
        if (preg_match('/BIOS Model name:\s+(.*)/i', $lscpu_out, $m)) $cpu_model = trim($m[1]);
        else if (preg_match('/Model name:\s+(.*)/i', $lscpu_out, $m)) $cpu_model = trim($m[1]);
    }

    // Method 2: /proc/cpuinfo fallback
    if ($cpu_model === 'Unknown CPU' && ($cpu_info = @file_get_contents('/proc/cpuinfo'))) {
        if (preg_match('/model name\s+:\s+(.*)/i', $cpu_info, $m)) $cpu_model = trim($m[1]);
        else if (preg_match('/Processor\s+:\s+(.*)/i', $cpu_info, $m)) $cpu_model = trim($m[1]);
        
        // Handle ARM Implementer codes if still unknown
        if ($cpu_model === 'Unknown CPU' || $cpu_model === '0') {
            if (preg_match('/CPU implementer\s+:\s+(0x[0-9a-f]+)/i', $cpu_info, $m)) {
                $impl = hexdec($m[1]);
                $vendors = [0x41 => 'ARM', 0x43 => 'Cavium', 0x48 => 'HiSilicon', 0x51 => 'Qualcomm', 0x63 => 'Ampere', 0x61 => 'Apple', 0x4e => 'nVidia'];
                if (isset($vendors[$impl])) {
                    $cpu_model = $vendors[$impl];
                    if (preg_match('/CPU part\s+:\s+(0x[0-9a-f]+)/i', $cpu_info, $m2)) {
                        $part = hexdec($m2[1]);
                        if ($impl == 0x63 && $part == 0x001) $cpu_model = 'Ampere Altra';
                        else if ($impl == 0x41 && $part == 0xd0c) $cpu_model = 'ARM Neoverse N1';
                        else $cpu_model .= " (Part 0x" . dechex($part) . ")";
                    }
                }
            }
        }
    }

    // Method 3: Device Tree (Raspberry Pi, etc.)
    if ($cpu_model === 'Unknown CPU' || stripos($cpu_model, 'BCM') !== false) {
        if ($dt_model = @file_get_contents('/proc/device-tree/model')) {
            $cpu_model = trim($dt_model) . ($cpu_model !== 'Unknown CPU' ? " ($cpu_model)" : "");
        }
    }
    
    // Final Cleanup: If it's just "0" or empty, set to Unknown
    if (empty($cpu_model) || $cpu_model === '0') $cpu_model = 'Unknown CPU';
    $kernel = php_uname('r');
    $arch = php_uname('m');

    $prev_cpu = $read_cpu();
    $prev_net = $read_net();
    
    // Initial Disk I/O state
    $read_disk_io = function() {
        $data = @file_get_contents('/proc/diskstats');
        if (!$data) return [];
        $stats = [];
        foreach (explode("\n", trim($data)) as $line) {
            $p = preg_split('/\s+/', trim($line));
            if (count($p) < 14) continue;
            $dev = $p[2];
            if (strpos($dev, 'loop') === 0 || strpos($dev, 'ram') === 0) continue;
            $stats[$dev] = ['r' => (float)$p[5] * 512, 'w' => (float)$p[9] * 512]; // sectors to bytes
        }
        return $stats;
    };
    $prev_disk_io = $read_disk_io();
    $prev_time = microtime(true);

    // Release session lock to allow other requests (like page refresh) while streaming
    session_write_close();

    // --- CPU socket topology: logical CPU id -> physical package id (socket) ---
    $cpu_to_package = [];
    foreach (glob('/sys/devices/system/cpu/cpu[0-9]*') ?: [] as $dir) {
        if (!preg_match('/cpu(\d+)$/', basename($dir), $m)) {
            continue;
        }
        $cpuid = (int)$m[1];
        $pkgFile = $dir . '/topology/physical_package_id';
        if (file_exists($pkgFile)) {
            $cpu_to_package[$cpuid] = (int)trim((string)@file_get_contents($pkgFile));
        }
    }
    if ($cpu_to_package === []) {
        foreach ($read_cpu() as $name => $_) {
            if ($name === 'total') {
                continue;
            }
            if (preg_match('/^cpu(\d+)$/', $name, $m)) {
                $cpu_to_package[(int)$m[1]] = 0;
            }
        }
    }
    $package_ids = array_values(array_unique(array_values($cpu_to_package)));
    sort($package_ids, SORT_NUMERIC);
    if ($package_ids === []) {
        $package_ids = [0];
    }

    $read_cpu_package_temps = function () {
        $temps = [];
        foreach (glob('/sys/class/hwmon/hwmon*') ?: [] as $hwmon) {
            foreach (glob($hwmon . '/temp*_label') ?: [] as $lf) {
                $label = trim((string)@file_get_contents($lf));
                if ($label === '') {
                    continue;
                }
                if (preg_match('/package id\s*(\d+)/i', $label, $m)) {
                    $pid = (int)$m[1];
                    $input = preg_replace('/_label$/', '_input', $lf);
                    if (file_exists($input)) {
                        $v = (float)@file_get_contents($input);
                        if ($v > 0) {
                            $c = $v / 1000;
                            if ($c > 10 && $c < 110) {
                                if (!isset($temps[$pid]) || $c > $temps[$pid]) {
                                    $temps[$pid] = $c;
                                }
                            }
                        }
                    }
                }
            }
        }
        return $temps;
    };

    // Process CPU sampler (delta against previous loop; avoids per-loop extra sleep)
    $read_proc_cpu = function($pids) {
        $cpu_stats = [];
        $clk_tck = (int)shell_exec('getconf CLK_TCK 2>/dev/null') ?: 100;
        foreach ($pids as $pid) {
            $stat_file = "/proc/$pid/stat";
            if (file_exists($stat_file)) {
                $stat_content = @file_get_contents($stat_file);
                if ($stat_content) {
                    // Comm can contain spaces and parentheses, so find the last ')'
                    $last_paren = strrpos($stat_content, ')');
                    if ($last_paren !== false) {
                        $fields = explode(' ', substr($stat_content, $last_paren + 2));
                        if (count($fields) >= 12) {
                            $utime = (int)$fields[11];
                            $stime = (int)$fields[12];
                            $cpu_stats[$pid] = ['utime' => $utime, 'stime' => $stime, 'clk_tck' => $clk_tck];
                        }
                    }
                }
            }
        }
        return $cpu_stats;
    };
    $prev_proc = [];
    $prev_time_proc = microtime(true);

    // Initial small wait to get first delta quickly
    usleep(200000);

    while (true) {
        $start_loop = microtime(true);
        
        $curr_cpu = $read_cpu();
        $curr_net = $read_net();
        $curr_disk_io = $read_disk_io();
        $curr_time = microtime(true);
        $interval = $curr_time - $prev_time;
        if ($interval <= 0) $interval = 1;

        $stats = ['cpu' => ['usage' => 0, 'cores' => []], 'network' => [], 'disk_io' => ['r' => 0, 'w' => 0]];

        // Calculate CPU delta
        foreach ($curr_cpu as $name => $c2) {
            $c1 = $prev_cpu[$name] ?? ['idle' => 0, 'total' => 0];
            $diff_total = $c2['total'] - $c1['total'];
            $diff_idle = $c2['idle'] - $c1['idle'];
            $usage = $diff_total > 0 ? (1 - ($diff_idle / $diff_total)) * 100 : 0;
            if ($name === 'total') $stats['cpu']['usage'] = $usage;
            else $stats['cpu']['cores'][] = ['load' => $usage];
        }

        // Calculate Network delta
        foreach ($curr_net as $iface => $d2) {
            $d1 = $prev_net[$iface] ?? ['rx' => 0, 'tx' => 0];
            $stats['network'][] = [
                'interface' => $iface,
                'rx_speed' => ($d2['rx'] - $d1['rx']) / $interval,
                'tx_speed' => ($d2['tx'] - $d1['tx']) / $interval,
                'rxTotal' => $d2['rx'],
                'txTotal' => $d2['tx']
            ];
        }

        // Calculate Disk I/O delta - per disk
        $stats['disk_io'] = ['r' => 0, 'w' => 0, 'perDisk' => []];
        foreach ($curr_disk_io as $dev => $d2) {
            $d1 = $prev_disk_io[$dev] ?? ['r' => 0, 'w' => 0];
            $dev_r = ($d2['r'] - $d1['r']) / $interval;
            $dev_w = ($d2['w'] - $d1['w']) / $interval;
            $stats['disk_io']['r'] += $dev_r;
            $stats['disk_io']['w'] += $dev_w;
            $stats['disk_io']['perDisk'][$dev] = ['r' => $dev_r, 'w' => $dev_w];
        }

        $prev_cpu = $curr_cpu;
        $prev_net = $curr_net;
        $prev_disk_io = $curr_disk_io;
        $prev_time = $curr_time;

        // --- Memory & Swap ---
        $meminfo = @file_get_contents('/proc/meminfo') ?: '';
        $mem = [];
        foreach (explode("\n", $meminfo) as $line) {
            if (preg_match('/^(\w+):\s+(\d+)/', $line, $m)) $mem[$m[1]] = (int)$m[2] * 1024;
        }
        $total = $mem['MemTotal'] ?? 0;
        $avail = $mem['MemAvailable'] ?? (($mem['MemFree'] ?? 0) + ($mem['Buffers'] ?? 0) + ($mem['Cached'] ?? 0));
        $used = $total - $avail;
        
        $sTotal = $mem['SwapTotal'] ?? 0;
        $sFree = $mem['SwapFree'] ?? 0;
        $sUsed = $sTotal - $sFree;
        
        $stats['memory'] = [
            'total' => $total, 'used' => $used, 'percentage' => $total > 0 ? ($used / $total) * 100 : 0,
            'swapTotal' => $sTotal, 'swapUsed' => $sUsed, 'swapPercentage' => $sTotal > 0 ? ($sUsed / $sTotal) * 100 : 0
        ];

        // --- Load Avg & Temp ---
        $load = explode(' ', @file_get_contents('/proc/loadavg') ?: '0 0 0');
        
        $all_temps = [];
        // Scan thermal zones
        foreach (glob('/sys/class/thermal/thermal_zone*/temp') as $f) {
            $val = (float)@file_get_contents($f);
            if ($val > 0) $all_temps[] = $val / 1000;
        }
        // Scan hwmon sensors
        foreach (glob('/sys/class/hwmon/hwmon*/temp*_input') as $f) {
            $val = (float)@file_get_contents($f);
            if ($val > 0) $all_temps[] = $val / 1000;
        }
        
        // Filter realistic CPU temps (10-110 C) and pick the highest
        $cpu_temps = array_filter($all_temps, function($t) { return $t > 10 && $t < 110; });
        $temp = !empty($cpu_temps) ? max($cpu_temps) : 0;
        
        $stats['load'] = array_slice($load, 0, 3);
        $stats['temp'] = $temp;

        $package_temps = $read_cpu_package_temps();
        $nCores = count($stats['cpu']['cores']);
        $cpu_packages = [];
        foreach ($package_ids as $pkgId) {
            $cpuIdsForPkg = [];
            foreach ($cpu_to_package as $cpuId => $p) {
                if ((int)$p === (int)$pkgId) {
                    $cpuIdsForPkg[] = (int)$cpuId;
                }
            }
            sort($cpuIdsForPkg, SORT_NUMERIC);
            $loads = [];
            $pcores = [];
            foreach ($cpuIdsForPkg as $cpuId) {
                if ($cpuId < $nCores && isset($stats['cpu']['cores'][$cpuId])) {
                    $loads[] = $stats['cpu']['cores'][$cpuId]['load'];
                    $pcores[] = $stats['cpu']['cores'][$cpuId];
                }
            }
            $pkgUsage = count($loads) > 0 ? array_sum($loads) / count($loads) : 0;
            $sockTemp = isset($package_temps[$pkgId]) ? $package_temps[$pkgId] : $temp;
            $cpu_packages[] = [
                'index' => (int)$pkgId,
                'usage' => $pkgUsage,
                'cores' => count($pcores),
                'temp' => $sockTemp,
                'model' => $cpu_model,
                'perCore' => $pcores,
            ];
        }

        // --- Disk Space ---
        $stats['disk'] = [];
        $df = shell_exec('df -PB1 2>/dev/null');
        if ($df) {
            $lines = explode("\n", trim($df));
            array_shift($lines);
            foreach ($lines as $line) {
                $p = preg_split('/\s+/', $line);
                if (count($p) >= 6 && strpos($p[0], '/dev/') === 0) {
                    $stats['disk'][] = ['letter' => $p[0], 'size' => (float)$p[1], 'used' => (float)$p[2]];
                }
            }
        }

        // --- Processes ---
        // Get list of top processes by CPU (for sorting) and their memory usage
        $ps = shell_exec('ps -eo pid,comm,%mem --sort=-%mem | head -n 11 2>/dev/null');
        $stats['processes'] = [];
        $proc_pids = [];
        if ($ps) {
            $lines = explode("\n", trim($ps));
            array_shift($lines);
            foreach ($lines as $line) {
                $p = preg_split('/\s+/', trim($line));
                if (count($p) >= 3) {
                    $pid = $p[0];
                    $proc_pids[] = $pid;
                    $stats['processes'][$pid] = ['pid' => $pid, 'name' => $p[1], 'cpu' => 0.0, 'mem' => (float)$p[2]];
                }
            }
        }

        // Calculate process CPU usage delta using previous loop snapshot
        $curr_proc = $read_proc_cpu($proc_pids);
        $curr_time_proc = microtime(true);
        $proc_interval = $curr_time_proc - $prev_time_proc;

        // Calculate CPU usage delta for each process
        if ($proc_interval > 0 && !empty($prev_proc)) {
            foreach ($proc_pids as $pid) {
                if (isset($curr_proc[$pid]) && isset($prev_proc[$pid])) {
                    $curr_total = $curr_proc[$pid]['utime'] + $curr_proc[$pid]['stime'];
                    $prev_total = $prev_proc[$pid]['utime'] + $prev_proc[$pid]['stime'];
                    $diff_total = $curr_total - $prev_total;
                    // Convert clock ticks to seconds and calculate percentage
                    $cpu_usage = ($diff_total / $curr_proc[$pid]['clk_tck']) / $proc_interval * 100;
                    $stats['processes'][$pid]['cpu'] = round($cpu_usage, 1);
                }
            }
        }
        $prev_proc = $curr_proc;
        $prev_time_proc = $curr_time_proc;

        // Re-sort by real-time CPU usage
        usort($stats['processes'], function($a, $b) {
            return $b['cpu'] <=> $a['cpu'];
        });
        $stats['processes'] = array_values($stats['processes']);

        $uptime = (float)@file_get_contents('/proc/uptime') ?: 0;

        $ips = [];
        $ip_out = shell_exec('ip -o -4 addr list 2>/dev/null');
        if ($ip_out) {
            foreach (explode("\n", trim($ip_out)) as $line) {
                if (preg_match('/^\d+:\s+(\S+)\s+inet\s+([^\/\s]+)/', $line, $m)) {
                    $ips[] = ['interface' => $m[1], 'ip' => $m[2]];
                }
            }
        }

        // --- GPU Stats ---
        $gpu_max_freq = 0;
        $gpus = [];

        // NVIDIA first: one entry per physical GPU (CSV fields may contain commas — use str_getcsv)
        // Include power draw/limit + throttle reasons so we can show Power and Limit info on the card
        $nvidia_csv = shell_exec('nvidia-smi --query-gpu=index,name,utilization.gpu,utilization.memory,memory.total,memory.used,temperature.gpu,clocks.current.graphics,power.draw,power.limit,clocks_throttle_reasons.active --format=csv,noheader,nounits 2>/dev/null');
        if ($nvidia_csv !== null && trim($nvidia_csv) !== '') {
            foreach (explode("\n", trim($nvidia_csv)) as $line) {
                if ($line === '') {
                    continue;
                }
                $p = str_getcsv($line);
                // Minimum fields we need for Power: index,name,utilization.gpu,utilization.memory,memory.total,memory.used,temperature.gpu,clocks.current.graphics,power.draw,power.limit
                if (count($p) < 10) {
                    continue;
                }
                $mem_total_mib = (float)trim($p[4]);
                $mem_used_mib = (float)trim($p[5]);
                $mem_total_bytes = (int)round($mem_total_mib * 1024 * 1024);
                $mem_used_bytes = (int)round($mem_used_mib * 1024 * 1024);
                $mem_used_pct = $mem_total_mib > 0 ? (int)round($mem_used_mib / $mem_total_mib * 100) : 0;
                $temp_raw = trim($p[6]);
                $freq_raw = trim($p[7]);
                $pwr_draw_raw = trim($p[8]);
                $pwr_cap_raw = trim($p[9]);
                $limit_reason_raw = count($p) > 10 ? trim($p[10]) : '';
                $limit_reason = ($limit_reason_raw !== '' && strtolower($limit_reason_raw) !== 'n/a') ? $limit_reason_raw : null;
                $temp = preg_match('/^[\d.]+$/', $temp_raw) ? (float)$temp_raw : 0;
                $freq = preg_match('/^[\d.]+$/', $freq_raw) ? (int)$freq_raw : 0;
                $pwr_draw = preg_match('/^[\d.]+$/', $pwr_draw_raw) ? (float)$pwr_draw_raw : null;
                $pwr_cap = preg_match('/^[\d.]+$/', $pwr_cap_raw) ? (float)$pwr_cap_raw : null;

                // Map clocks_throttle_reasons.active hex bitmask to human-readable English reasons
                $limit_reason = null;
                $mask_str = strtolower($limit_reason_raw);
                if ($mask_str !== '' && $mask_str !== 'n/a' && preg_match('/^0x[0-9a-f]+$/', $mask_str)) {
                    $mask_val = hexdec($mask_str);
                    $reason_map = [
                        0x0000000000000000 => 'None',
                        0x0000000000000001 => 'GPU Idle',
                        0x0000000000000002 => 'Applications Clocks Setting',
                        0x0000000000000004 => 'SW Power Cap',
                        0x0000000000000008 => 'HW Slowdown',
                        0x0000000000000010 => 'Sync Boost',
                        0x0000000000000020 => 'SW Thermal Slowdown',
                        0x0000000000000040 => 'HW Thermal Slowdown',
                        0x0000000000000080 => 'HW Power Brake Slowdown',
                        0x0000000000000100 => 'Display Clock Setting',
                    ];

                    if ($mask_val === 0 && isset($reason_map[0])) {
                        $limit_reason = $reason_map[0];
                    } else {
                        $reasons = [];
                        foreach ($reason_map as $bit => $label) {
                            if ($bit === 0) continue;
                            if (($mask_val & $bit) !== 0) {
                                $reasons[] = $label;
                            }
                        }
                        if (!empty($reasons)) {
                            $limit_reason = implode(', ', $reasons);
                        }
                    }
                }
                $gpus[] = [
                    'index' => (int)trim($p[0]),
                    'name' => trim($p[1]),
                    'vendor' => 'nvidia',
                    'available' => true,
                    'usage' => (float)trim($p[2]),
                    'memory_utilization' => (float)trim($p[3]),
                    'memory_used_pct' => $mem_used_pct,
                    'memory' => ['used' => $mem_used_bytes, 'total' => $mem_total_bytes],
                    'temp' => $temp,
                    'freq' => $freq,
                    'power_draw' => $pwr_draw,
                    'power_cap' => $pwr_cap,
                    'limit_reason' => $limit_reason,
                ];
            }
        }

        $gpu = ['available' => false, 'usage' => 0, 'memory' => ['used' => 0, 'total' => 0], 'temp' => 0, 'freq' => 0, 'hasDevice' => false, 'name' => 'GPU'];

        if (empty($gpus)) {
        // Method 0: Get actual GPU Model Name via lspci
        $gpu_model_name = '';
        $lspci_out = shell_exec('lspci -mm 2>/dev/null');
        if ($lspci_out) {
            foreach (explode("\n", $lspci_out) as $line) {
                if (stripos($line, 'VGA') !== false || stripos($line, 'Display') !== false || stripos($line, '3D') !== false) {
                    // Format: 00:02.0 "VGA compatible controller" "Intel Corporation" "UHD Graphics 620" ...
                    if (preg_match('/"(?:Intel|NVIDIA|AMD)[^"]*"\s+"([^"]+)"/', $line, $m)) {
                        $gpu_model_name = $m[1];
                        break;
                    }
                }
            }
        }
        if (!$gpu_model_name) {
            $gpu_model_name = (strpos(@file_get_contents('/proc/cpuinfo'), 'Intel') !== false) ? 'Intel HD Graphics' : 'Unknown GPU';
        }
        $gpu['name'] = 'GPU: ' . $gpu_model_name;

        // Check for Intel i915 GPU via multiple methods
        // Method 1: DRM card device (prefer card1 for Intel GPUs on some systems)
        $drm_card = null;
        if (file_exists('/sys/class/drm/card1')) {
            $drm_card = '/sys/class/drm/card1'; // Intel GPU often on card1
        } elseif (file_exists('/sys/class/drm/card0')) {
            $drm_card = '/sys/class/drm/card0';
        } else {
            $cards = glob('/sys/class/drm/card*');
            if (!empty($cards)) $drm_card = $cards[0];
        }
        
        // Method 2: Check if i915 driver is loaded
        $i915_loaded = false;
        $i915_info = @file_get_contents('/proc/modules');
        if ($i915_info && strpos($i915_info, 'i915') !== false) {
            $i915_loaded = true;
            $gpu['hasDevice'] = true;
        }
        
        if ($drm_card) {
            $gpu['hasDevice'] = true;
            $gpu['available'] = true;
            
            // Read current and max frequency
            $gpu_freq = @file_get_contents($drm_card . '/gt_cur_freq_mhz');
            $gpu_max_freq = @file_get_contents($drm_card . '/gt_max_freq_mhz');
            
            if ($gpu_freq !== false && is_numeric(trim($gpu_freq))) {
                $gpu['freq'] = (int)trim($gpu_freq);
            } else {
                $gpu['freq'] = 0;
            }
            
            if ($gpu_max_freq !== false && is_numeric(trim($gpu_max_freq))) {
                $gpu_max_freq = (int)trim($gpu_max_freq);
            } else {
                $gpu_max_freq = 1100; // Default max for i5-8250U
            }
            
            // Try to read engine busy times for real GPU usage
            $engine_busy_total = 0;
            $engine_count = 0;
            $engine_dirs = @glob($drm_card . '/engine/*');
            
            if ($engine_dirs && is_array($engine_dirs)) {
                foreach ($engine_dirs as $eng_dir) {
                    $busy_file = $eng_dir . '/busy';
                    if (file_exists($busy_file)) {
                        $busy = @file_get_contents($busy_file);
                        if ($busy !== false && is_numeric(trim($busy))) {
                            $engine_busy_total += (int)trim($busy);
                            $engine_count++;
                        }
                    }
                }
            }
            
            // Calculate usage from engine busy times if available
            if ($engine_count > 0) {
                $uptime_str = @file_get_contents('/proc/uptime');
                if ($uptime_str !== false) {
                    $uptime_secs = (float)trim($uptime_str);
                    $uptime_ns = $uptime_secs * 1000000000;
                    
                    if ($uptime_ns > 0) {
                        $gpu['usage'] = min(100, max(0, ($engine_busy_total / $engine_count) / $uptime_ns * 100));
                    } else {
                        $gpu['usage'] = 0;
                    }
                } else {
                    $gpu['usage'] = 0;
                }
            } else {
                // No busy files - show frequency only
                $gpu['usage'] = 0;
                $gpu['freq_info'] = $gpu['freq'] . '/' . $gpu_max_freq . ' MHz';
            }

            // GPU memory for Intel (shared) - used is gem objects, total is system shared
            if (file_exists('/sys/kernel/debug/dri/0/i915_gem_objects')) {
                $gem = @file_get_contents('/sys/kernel/debug/dri/0/i915_gem_objects');
                if (preg_match('/(\d+)\s+objects/', $gem, $m)) $gpu['memory']['used'] = (int)$m[1]; // simplified
            }
            // Fallback: estimate VRAM from system total for integrated
            $gpu['memory']['total'] = $total > 0 ? $total * 0.1 : 2048 * 1024 * 1024; // Assume 10% shared or 2GB

            // GPU temp
            foreach (glob($drm_card . '/device/hwmon/hwmon*/temp*_input') as $f) {
                $val = (float)@file_get_contents($f);
                if ($val > 0) { $gpu['temp'] = $val / 1000; break; }
            }
            // Fallback to CPU temp if GPU temp is missing (common on Intel laptop chips like i5-8250u)
            if ($gpu['temp'] <= 0 && $temp > 0) $gpu['temp'] = $temp;
        }
        
        // Method 5: intel_gpu_top (Actual engine utilization)
        if (file_exists('/usr/bin/intel_gpu_top')) {
            $igt = shell_exec('timeout 0.2 intel_gpu_top -J -s 100 2>/dev/null');
            if ($igt && preg_match('/\{.*\}/s', $igt, $m)) {
                $igt_data = json_decode($m[0], true);
                if ($igt_data) {
                    $gpu['available'] = true;
                    $gpu['usage'] = $igt_data['engines']['Render/3D/0']['busy'] ?? $gpu['usage'];
                    if (isset($igt_data['frequency']['actual'])) $gpu['freq'] = $igt_data['frequency']['actual'];
                }
            }
        }
        
        // Method 6: Intel xpu-smi (Better VRAM/Util if available)
        if (file_exists('/usr/bin/xpu-smi')) {
            $xpu = shell_exec('timeout 0.3 xpu-smi stats --json 2>/dev/null');
            $data = json_decode($xpu, true);
            if ($data && isset($data[0]['GPU'])) {
                $gpu['available'] = true;
                $gpu['usage'] = $data[0]['GPU']['utilization'] ?? $gpu['usage'];
                $gpu['memory']['used'] = ($data[0]['GPU']['vram_used'] ?? 0) * 1024 * 1024;
                $gpu['memory']['total'] = ($data[0]['GPU']['vram_total'] ?? 0) * 1024 * 1024;
                if ($data[0]['GPU']['temperature'] > 0) $gpu['temp'] = $data[0]['GPU']['temperature'];
            }
        }

        $mem = $gpu['memory'];
        $mem_pct = ($mem['total'] ?? 0) > 0 ? (int)round(($mem['used'] ?? 0) / $mem['total'] * 100) : 0;
        if ($gpu['hasDevice']) {
            $gpus[] = [
                'index' => 0,
                'name' => $gpu['name'],
                'vendor' => 'other',
                'available' => $gpu['available'],
                'usage' => $gpu['usage'],
                'memory_used_pct' => $mem_pct,
                'memory' => $gpu['memory'],
                'temp' => $gpu['temp'],
                'freq' => $gpu['freq'],
                'freq_info' => $gpu['freq_info'] ?? null,
            ];
        }
        }

        $gpu_first = $gpus[0] ?? null;
        $gpu_payload = array_merge(
            [
                'hasDevice' => false,
                'available' => false,
                'name' => 'GPU: Unknown GPU',
                'usage' => 0,
                'memory' => ['used' => 0, 'total' => 0],
                'memory_used_pct' => 0,
                'temp' => 0,
                'freq' => 0,
            ],
            $gpu_first ?: [],
            ['gpus' => $gpus, 'max_freq' => $gpu_max_freq]
        );
        if (!empty($gpus)) {
            $gpu_payload['hasDevice'] = true;
        }

        echo "data: " . json_encode([
            'timestamp' => date('c'),
            'cpu' => [
                'usage' => $stats['cpu']['usage'],
                'cores' => count($stats['cpu']['cores']),
                'model' => $cpu_model,
                'perCore' => $stats['cpu']['cores'],
                'temp' => $stats['temp'],
                'packages' => $cpu_packages,
            ],
            'memory' => array_merge($stats['memory'], ['speed' => $memory_speed]),
            'disk' => $stats['disk'],
            'disk_io' => $stats['disk_io'],
            'network' => $stats['network'],
            'networkHistory' => ['download' => array_sum(array_column($stats['network'], 'rx_speed')), 'upload' => array_sum(array_column($stats['network'], 'tx_speed'))],
            'processes' => $stats['processes'],
            'gpu' => $gpu_payload,
            'system' => [
                'os' => ['distro' => $distro, 'release' => $kernel, 'arch' => $arch],
                'uptime' => $uptime,
                'load' => $stats['load'],
                'network' => ['interfaces' => $ips],
                'host' => $hostname,
            ]
        ]) . "\n\n";

        if (ob_get_level() > 0) ob_flush();
        flush();
        if (connection_aborted()) break;

        $elapsed = microtime(true) - $start_loop;
        $sleep_time = 1.0 - $elapsed;
        if ($sleep_time > 0) {
            usleep($sleep_time * 1000000);
        }
    }
    exit;
}

$monitorRemoteNode = '';
if ($monitorIsCentral && isset($_GET['node'])) {
    $requestedNode = (string)$_GET['node'];
    if (!preg_match('/^[A-Za-z0-9._-]{1,80}$/', $requestedNode)) monitorJsonResponse(['ok' => false, 'error' => 'Invalid node'], 400);
    $monitorRemoteNode = $requestedNode;
}

if ($monitorIsCentral && !isset($_GET['local']) && $monitorRemoteNode === '') {
    $centralUrl = htmlspecialchars((string)($monitorConfig['central_url'] ?? ''), ENT_QUOTES, 'UTF-8');
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Infrastructure Overview - <?php echo htmlspecialchars($hostname, ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { box-sizing: border-box; }
        body { margin: 0; background: #101214; color: #e8eaed; font-family: Roboto, sans-serif; }
        .shell { width: min(1480px, calc(100% - 32px)); margin: 0 auto; }
        .topbar { min-height: 76px; display: flex; align-items: center; justify-content: space-between; gap: 20px; border-bottom: 1px solid #2a2e33; }
        .brand { display: flex; align-items: center; gap: 13px; min-width: 0; }
        .brand-mark { width: 38px; height: 38px; display: grid; place-items: center; border: 1px solid #3b434b; background: #1b2025; color: #55c7f3; border-radius: 7px; }
        h1 { margin: 0; font-size: 21px; line-height: 1.2; letter-spacing: 0; }
        .subtitle { margin-top: 4px; color: #8d969f; font-size: 12px; }
        .actions { display: flex; align-items: center; gap: 10px; }
        .action { color: #dbe2e8; text-decoration: none; border: 1px solid #38414a; background: #191d21; padding: 9px 12px; border-radius: 6px; font-size: 13px; }
        .summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border-bottom: 1px solid #2a2e33; }
        .summary-item { padding: 22px 18px; border-right: 1px solid #2a2e33; }
        .summary-item:first-child { padding-left: 0; }
        .summary-item:last-child { border-right: 0; }
        .summary-label { color: #8d969f; text-transform: uppercase; font-size: 10px; letter-spacing: .8px; }
        .summary-value { margin-top: 7px; font-size: 27px; font-weight: 700; }
        .summary-note { margin-top: 3px; color: #77818a; font-size: 11px; }
        .content-head { display: flex; justify-content: space-between; align-items: end; gap: 20px; padding: 26px 0 14px; }
        .content-head h2 { margin: 0; font-size: 16px; }
        .stream-state { color: #9aa3ac; font-size: 12px; display: flex; align-items: center; gap: 7px; }
        .stream-dot, .node-dot { width: 8px; height: 8px; border-radius: 50%; background: #7e8790; }
        .stream-dot.live, .node-dot.online { background: #46c277; box-shadow: 0 0 8px rgba(70,194,119,.45); }
        .node-dot.degraded { background: #f1ad45; }
        .node-dot.offline { background: #ef6262; }
        .node-groups { padding-bottom: 36px; }
        .node-section + .node-section { margin-top: 28px; }
        .group-heading { display: flex; align-items: center; gap: 9px; margin: 0 0 12px; color: #cdd4da; font-size: 13px; font-weight: 700; }
        .group-count { display: inline-grid; place-items: center; min-width: 22px; height: 20px; padding: 0 6px; border: 1px solid #343c44; border-radius: 10px; color: #7f8a94; font-size: 10px; font-weight: 500; }
        .node-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(330px, 1fr)); gap: 14px; }
        .node { display: block; color: inherit; text-decoration: none; background: #181c20; border: 1px solid #2d3339; border-radius: 7px; overflow: hidden; transition: border-color .15s, transform .15s; }
        .node:hover { border-color: #4b5965; transform: translateY(-1px); }
        .node-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 15px; padding: 17px 18px 14px; border-bottom: 1px solid #292f35; }
        .node-name { font-size: 15px; font-weight: 700; overflow-wrap: anywhere; }
        .node-os { margin-top: 5px; color: #88929b; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 250px; }
        .node-status { display: flex; align-items: center; gap: 7px; color: #aab2b9; font-size: 11px; text-transform: uppercase; }
        .metrics { display: grid; grid-template-columns: 1fr 1fr; }
        .metric { padding: 14px 18px; border-bottom: 1px solid #292f35; }
        .metric:nth-child(odd) { border-right: 1px solid #292f35; }
        .metric-label { color: #89939c; font-size: 10px; text-transform: uppercase; }
        .metric-value { margin-top: 6px; font-size: 18px; font-weight: 700; }
        .meter { height: 4px; background: #30363c; margin-top: 8px; overflow: hidden; border-radius: 2px; }
        .meter span { display: block; height: 100%; background: #52b9e4; }
        .meter.warn span { background: #f1ad45; }
        .meter.critical span { background: #ef6262; }
        .node-foot { display: flex; justify-content: space-between; gap: 10px; padding: 11px 18px; color: #828c95; font-size: 11px; }
        .empty { grid-column: 1 / -1; padding: 55px 20px; border: 1px dashed #343b42; text-align: center; color: #8c969f; }
        footer { border-top: 1px solid #2a2e33; color: #69737c; font-size: 11px; padding: 18px 0 25px; }
        @media (max-width: 720px) {
            .shell { width: min(100% - 20px, 1480px); }
            .topbar { align-items: flex-start; padding: 16px 0; }
            .actions { flex-direction: column; align-items: stretch; }
            .summary { grid-template-columns: 1fr 1fr; }
            .summary-item { border-bottom: 1px solid #2a2e33; }
            .summary-item:nth-child(2) { border-right: 0; }
            .summary-item:nth-child(3), .summary-item:nth-child(4) { border-bottom: 0; }
            .summary-item:first-child, .summary-item:nth-child(3) { padding-left: 0; }
            .node-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="shell">
        <header class="topbar">
            <div class="brand">
                <div class="brand-mark"><i class="fas fa-server"></i></div>
                <div><h1>Infrastructure Overview</h1><div class="subtitle">Distributed server monitor</div></div>
            </div>
            <div class="actions"><a class="action" href="?local=1"><i class="fas fa-chart-line"></i>&nbsp; Local details</a></div>
        </header>
        <section class="summary">
            <div class="summary-item"><div class="summary-label">Registered</div><div class="summary-value" id="sum-total">0</div><div class="summary-note">Monitored nodes</div></div>
            <div class="summary-item"><div class="summary-label">Online</div><div class="summary-value" id="sum-online">0</div><div class="summary-note">Reporting normally</div></div>
            <div class="summary-item"><div class="summary-label">Attention</div><div class="summary-value" id="sum-attention">0</div><div class="summary-note">Degraded or offline</div></div>
            <div class="summary-item"><div class="summary-label">Last update</div><div class="summary-value" id="sum-time" style="font-size:20px">--:--:--</div><div class="summary-note">Central server time</div></div>
        </section>
        <div class="content-head">
            <h2>Servers</h2>
            <div class="stream-state"><span class="stream-dot" id="stream-dot"></span><span id="stream-label">Connecting</span></div>
        </div>
        <main class="node-groups" id="node-groups"><div class="empty">Waiting for the first Agent report...</div></main>
        <footer>Central endpoint: <?php echo $centralUrl ?: 'Not configured'; ?></footer>
    </div>
    <script>
        const esc = value => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
        const bytes = value => {
            const n = Number(value || 0); if (!n) return '0 B';
            const units = ['B','KB','MB','GB','TB']; const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
            return (n / 1024 ** i).toFixed(i > 2 ? 1 : 0) + ' ' + units[i];
        };
        const percent = value => Math.max(0, Math.min(100, Number(value || 0)));
        const ageText = age => age < 5 ? 'just now' : age < 60 ? `${age}s ago` : age < 3600 ? `${Math.floor(age / 60)}m ago` : `${Math.floor(age / 3600)}h ago`;
        const uptimeText = seconds => { const d = Math.floor(seconds / 86400), h = Math.floor(seconds % 86400 / 3600); return d ? `${d}d ${h}h` : `${h}h`; };
        const meterClass = value => value >= 90 ? 'critical' : value >= 75 ? 'warn' : '';
        function metric(label, value, pct) {
            return `<div class="metric"><div class="metric-label">${label}</div><div class="metric-value">${value}</div><div class="meter ${meterClass(pct)}"><span style="width:${percent(pct)}%"></span></div></div>`;
        }
        function nodeCard(n) {
            const m = n.metrics || {}, mem = m.memory || {}, disk = m.disk || {}, net = m.network || {}, gpu = m.gpu || {}, sys = n.system || {};
            const gpuPct = gpu.available ? percent(gpu.usage) : 0;
            const gpuValue = gpu.available ? `${Math.round(gpuPct)}%` : 'Not detected';
            const detailHref = n.is_local ? '?local=1' : `?node=${encodeURIComponent(n.node_id)}`;
            return `<a class="node" href="${detailHref}">
                <div class="node-top"><div><div class="node-name">${esc(n.node_id)}</div><div class="node-os">${esc(sys.os || 'System information pending')}</div></div><div class="node-status"><span class="node-dot ${esc(n.status)}"></span>${esc(n.status)}</div></div>
                <div class="metrics">
                    ${metric('CPU', `${Math.round(percent(m.cpu?.usage))}%`, m.cpu?.usage)}
                    ${metric('Memory', `${Math.round(percent(mem.percentage))}%`, mem.percentage)}
                    ${metric('Disk', `${Math.round(percent(disk.percentage))}%`, disk.percentage)}
                    ${metric('GPU', gpuValue, gpuPct)}
                </div>
                <div class="node-foot"><span>↓ ${bytes(net.rx_speed)}/s · ↑ ${bytes(net.tx_speed)}/s</span><span>Uptime ${uptimeText(m.uptime || 0)} · ${ageText(n.age_seconds || 0)}</span></div>
            </a>`;
        }
        function render(data) {
            const nodes = Array.isArray(data.nodes) ? data.nodes : [];
            const online = nodes.filter(n => n.status === 'online').length;
            document.getElementById('sum-total').textContent = nodes.length;
            document.getElementById('sum-online').textContent = online;
            document.getElementById('sum-attention').textContent = nodes.length - online;
            document.getElementById('sum-time').textContent = new Date((data.server_time || Date.now() / 1000) * 1000).toLocaleTimeString();
            const container = document.getElementById('node-groups');
            if (!nodes.length) { container.innerHTML = '<div class="empty">No Agents have registered yet.</div>'; return; }
            const ungrouped = nodes.filter(n => !String(n.group_name || '').trim());
            const grouped = new Map();
            nodes.filter(n => String(n.group_name || '').trim()).forEach(n => {
                const name = String(n.group_name).trim();
                if (!grouped.has(name)) grouped.set(name, []);
                grouped.get(name).push(n);
            });
            const sections = [];
            if (ungrouped.length) sections.push(`<section class="node-section"><div class="node-grid">${ungrouped.map(nodeCard).join('')}</div></section>`);
            [...grouped.keys()].sort((a, b) => a.localeCompare(b)).forEach(name => {
                const members = grouped.get(name);
                sections.push(`<section class="node-section"><h3 class="group-heading">${esc(name)}<span class="group-count">${members.length}</span></h3><div class="node-grid">${members.map(nodeCard).join('')}</div></section>`);
            });
            container.innerHTML = sections.join('');
        }
        const dot = document.getElementById('stream-dot'), label = document.getElementById('stream-label');
        const source = new EventSource('?monitor_api=overview_stream');
        source.onopen = () => { dot.classList.add('live'); label.textContent = 'Live'; };
        source.onmessage = event => { try { render(JSON.parse(event.data)); } catch (_) {} };
        source.onerror = () => { dot.classList.remove('live'); label.textContent = 'Reconnecting'; };
    </script>
</body>
</html>
    <?php
    exit;
}
$monitorAgentStatus = monitorSharedRead()['agent_status'];
$monitorConfigMessage = $_SESSION['monitor_config_message'] ?? null;
unset($_SESSION['monitor_config_message']);
$monitorPageHost = $monitorRemoteNode !== '' ? $monitorRemoteNode : $hostname;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Resource Monitor<?php echo $monitorPageHost ? ' - ' . htmlspecialchars($monitorPageHost, ENT_QUOTES, 'UTF-8') : ''; ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Roboto', sans-serif; background-color: #121212; color: #e0e0e0; padding: 0 10px 10px 10px; }
        .container { width: 100%; margin: 0 auto; }
        header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            padding: 25px 0; 
            border-bottom: 1px solid #333; 
            margin: 0 0 30px 0; 
        }
        h1 { 
            font-size: 28px; 
            color: #4fc3f7; 
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
            letter-spacing: -0.5px;
            line-height: 1;
        }
        .timestamp { 
            font-size: 14px; 
            color: #9e9e9e; 
            background: #252525;
            padding: 6px 12px;
            border-radius: 20px;
            border: 1px solid #333;
        }
        .header-actions { display: flex; align-items: center; gap: 10px; }
        .overview-button { display: inline-flex; align-items: center; gap: 7px; height: 30px; padding: 0 11px; color: #dce3e8; text-decoration: none; background: #252525; border: 1px solid #3a424a; border-radius: 6px; font-size: 12px; }
        .overview-button:hover { border-color: #4fc3f7; color: #4fc3f7; }
        .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card { background: #1e1e1e; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); border: 1px solid #333; display: flex; flex-direction: column; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; height: 28px; }
        .card-title { font-size: 18px; font-weight: 500; color: #4fc3f7; line-height: 1; }
        .card-value { font-size: 24px; font-weight: 700; margin: 5px 0; height: 32px; line-height: 32px; display: flex; align-items: center; }
        .card-chart-area { margin-top: auto; padding-top: 10px; border-top: 1px solid #2a2a2a; }
        .progress-container { width: 100%; height: 8px; background: #333; border-radius: 4px; overflow: hidden; margin: 8px 0; display: flex; }
        .progress-bar { height: 100%; transition: width 0.3s ease; }
        
        /* Standard Stats Grid */
        .card-stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 10px; min-height: 75px; align-content: start; }
        
        /* Memory Card - 3 column layout for Used/Total/Speed */
        .memory .card-stats-grid { grid-template-columns: 1fr 1fr 1fr; }
        .memory .stat-full { grid-column: span 3; }
        
        .stat-box { background: #252525; padding: 6px 8px; border-radius: 4px; border: 1px solid #333; display: flex; flex-direction: column; justify-content: center; }
        .stat-label { font-size: 10px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px; }
        .stat-value { font-size: 12px; color: #eee; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .stat-full { grid-column: span 2; }
        
        .cpu .progress-bar { background: #ff9800; }
        .memory .progress-bar { background: #2196f3; }
        .swap-mini-bar { height: 4px; background: #333; border-radius: 2px; overflow: hidden; margin-top: 4px; display: flex; }
        .swap-bar { background: #00bcd4 !important; }
        .disk .progress-bar { background: #9c27b0; }
        .gpu .progress-bar { background: #00e676; }
        .gpu .progress-bar.gpu-load-bar { background: #00e676; }
        .gpu .progress-bar.gpu-vram-bar { background: #69f0ae; }
        .gpu .gpu-meters-row { display: flex; gap: 12px; align-items: stretch; margin: 8px 0; }
        .gpu .gpu-meter { flex: 1; min-width: 0; }
        .gpu .progress-label-row { display: flex; justify-content: space-between; align-items: center; font-size: 12px; margin-bottom: 4px; color: #aaa; }
        .gpu .progress-label-row span:last-child { font-weight: 600; color: #e0e0e0; }
        .gpu .gpu-meter-value { font-size: 24px; font-weight: 700; line-height: 1; }
        .gpu .gpu-nv-stats { grid-template-columns: 1fr 1fr 1fr; }
        #cpu-cards-container { display: contents; }
        .gpu-grid { display: none; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .gpu-grid.gpu-cards-visible { display: grid; }
        #gpu-cards-container { display: contents; }
        .gpu .gpu-charts-row { display: flex; gap: 10px; align-items: stretch; }
        .gpu .gpu-chart-wrap { flex: 1; min-width: 0; }
        .gpu .gpu-chart-caption { font-size: 10px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px; }
        .gpu .gpu-chart-wrap .chart-container { height: 150px; margin-top: 0; position: relative; }
        .chart-container { height: 180px; margin-top: 5px; position: relative; }
        .grid-2col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        
        /* Usage Colors */
        .text-good { color: #4caf50; }
        .text-warning { color: #ff9800; }
        .text-critical { color: #f44336; }
        
        .progress-label { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; color: #aaa; }
        .temp-badge { background: #333; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #ff5722; border: 1px solid #444; }

        .processes-table { width: 100%; border-collapse: collapse; }
        .processes-table th, .processes-table td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }
        .processes-table th { color: #4fc3f7; font-weight: 500; }
        .cpu-cell { color: #ff9800; }
        .mem-cell { color: #2196f3; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; }
        .status-good { background: #4caf50; box-shadow: 0 0 5px #4caf50; }
        .status-warning { background: #ff9800; box-shadow: 0 0 5px #ff9800; }
        .status-critical { background: #f44336; box-shadow: 0 0 5px #f44336; }
        .toggle-btn, #network-interface-select { background: #333; color: #e0e0e0; border: 1px solid #555; border-radius: 4px; padding: 0 8px; cursor: pointer; font-size: 12px; height: 24px; line-height: 22px; box-sizing: border-box; vertical-align: middle; }
        .toggle-btn.active { background: #4fc3f7; color: #000; }
        .cpu-percore-container { margin-top: 10px; display: grid; grid-template-columns: repeat(auto-fill, minmax(80px, 1fr)); gap: 8px; max-height: 200px; overflow-y: auto; scrollbar-width: thin; scrollbar-color: #4a4a4a #1f1f1f; }
        .cpu-percore-container::-webkit-scrollbar { width: 10px; }
        .cpu-percore-container::-webkit-scrollbar-track { background: #1f1f1f; border-radius: 8px; }
        .cpu-percore-container::-webkit-scrollbar-thumb { background: #4a4a4a; border-radius: 8px; border: 2px solid #1f1f1f; }
        .cpu-percore-container::-webkit-scrollbar-thumb:hover { background: #5a5a5a; }
        .core-chart-container { height: 60px; position: relative; border: 1px solid #333; border-radius: 4px; }
        .core-chart-label { position: absolute; top: 1px; left: 3px; font-size: 9px; color: #bbb; z-index: 10; font-weight: 500; }
        .network-stats-row { display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 14px; }
        #network-interface-select { background: #333; color: #e0e0e0; border: 1px solid #555; border-radius: 4px; padding: 4px 8px; font-size: 12px; }
        #disk-select { background: #333; color: #e0e0e0; border: 1px solid #555; border-radius: 4px; padding: 4px 8px; font-size: 12px; }
        #connection-status { padding: 5px 10px; border-radius: 4px; font-size: 12px; margin-bottom: 10px; display: none; text-align: center; }
        .error { background: #f44336; color: white; }
        .central-settings { margin-top: 20px; }
        .agent-state { display: flex; align-items: center; gap: 7px; color: #9da5ad; font-size: 11px; }
        .agent-state-dot { width: 8px; height: 8px; border-radius: 50%; background: #ef6262; }
        .agent-state-dot.connected { background: #46c277; box-shadow: 0 0 7px rgba(70,194,119,.45); }
        .central-form { display: grid; grid-template-columns: minmax(220px, 2fr) minmax(150px, 1fr) minmax(140px, 1fr) 80px auto; gap: 10px; align-items: end; }
        .form-field { min-width: 0; }
        .form-field label { display: block; margin-bottom: 5px; color: #89939c; font-size: 10px; text-transform: uppercase; letter-spacing: .5px; }
        .form-field input { width: 100%; height: 36px; padding: 0 10px; border: 1px solid #3a424a; border-radius: 5px; background: #20252a; color: #edf0f2; outline: none; }
        .form-field input:focus { border-color: #4fc3f7; }
        .save-central { height: 36px; padding: 0 15px; border: 0; border-radius: 5px; background: #4fc3f7; color: #071116; font-weight: 700; cursor: pointer; }
        .config-message { margin-bottom: 12px; padding: 9px 11px; border-radius: 5px; font-size: 12px; border: 1px solid; }
        .config-message.success { color: #7edba2; background: rgba(70,194,119,.08); border-color: rgba(70,194,119,.3); }
        .config-message.error { color: #ff8f8f; background: rgba(239,98,98,.08); border-color: rgba(239,98,98,.3); }
        
        /* Enhanced System Info */
        .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }
        .info-item { display: flex; align-items: center; padding: 10px; background: #252525; border-radius: 6px; border: 1px solid #333; }
        .info-icon { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; background: #333; border-radius: 6px; margin-right: 12px; color: #4fc3f7; font-size: 16px; }
        .info-content { display: flex; flex-direction: column; width: 100%; }
        .info-label { font-size: 11px; color: #9e9e9e; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px; }
        .info-value { font-size: 14px; font-weight: 500; color: #e0e0e0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .nic-section { margin-top: 10px; border-top: 1px solid #333; padding-top: 15px; }
        .nic-section-title { font-size: 12px; font-weight: 600; color: #4fc3f7; margin-bottom: 10px; display: flex; align-items: center; }
        .nic-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: #252525; border-radius: 4px; margin-bottom: 6px; font-size: 13px; border: 1px solid #333; }
        .nic-name { font-weight: 500; color: #e0e0e0; display: flex; align-items: center; }
        .nic-ip { font-family: monospace; color: #4fc3f7; }

        /* Mobile Responsive - Bottom cards match top cards behavior */
        @media (max-width: 650px) {
            header { align-items: flex-start; gap: 12px; }
            h1 { font-size: 20px; line-height: 1.25; }
            .header-actions { flex-direction: column; align-items: flex-end; flex-shrink: 0; }
            .grid-2col { display: flex; flex-direction: column; }
            .info-grid { grid-template-columns: 1fr; }
            .central-form { grid-template-columns: 1fr; }
        }
        footer { margin-top: 40px; padding: 20px 0; border-top: 1px solid #333; text-align: center; color: #777; font-size: 14px; }
        footer a { color: #4fc3f7; text-decoration: none; }
        footer a:hover { text-decoration: underline; }
        .footer-content { display: flex; flex-direction: column; gap: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <div id="connection-status"></div>
        <header>
            <h1 id="page-title"><i class="fas fa-chart-line"></i> Server Resource Monitor<?php echo $monitorPageHost ? ' - ' . htmlspecialchars($monitorPageHost, ENT_QUOTES, 'UTF-8') : ''; ?></h1>
            <div class="header-actions">
                <?php if ($monitorIsCentral): ?><a class="overview-button" href="./"><i class="fas fa-arrow-left"></i> Return to overview</a><?php endif; ?>
                <div class="timestamp" id="current-time">Connecting...</div>
            </div>
        </header>

        <div class="dashboard-grid">
            <!-- CPU cards (one per physical socket; populated by JS) -->
            <div id="cpu-cards-container"></div>

            <!-- Memory Card -->
            <div class="card memory">
                <div class="card-header">
                    <div class="card-title">Memory</div>
                    <div class="status-indicator" id="memory-status"></div>
                </div>
                <div class="card-content">
                    <div class="card-value" id="memory-usage">0%</div>
                    <div class="progress-container"><div class="progress-bar" id="memory-bar" style="width: 0%"></div></div>
                    <div class="card-stats-grid">
                        <div class="stat-box"><span class="stat-label">Used</span><span class="stat-value" id="memory-used">0 GB</span></div>
                        <div class="stat-box"><span class="stat-label">Total</span><span class="stat-value" id="memory-total">0 GB</span></div>
                        <div class="stat-box"><span class="stat-label">Speed</span><span class="stat-value" id="memory-speed">-- MHz</span></div>
                        <div class="stat-box stat-full">
                            <span class="stat-label">Swap</span>
                            <div style="display: flex; align-items: center; gap: 8px; margin-top: 4px;">
                                <div style="flex: 1; height: 4px; background: #333; border-radius: 2px; overflow: hidden;">
                                    <div class="progress-bar swap-bar" id="swap-bar" style="width: 0%; height: 100%;"></div>
                                </div>
                                <span style="font-size: 9px; color: #777; min-width: 60px; text-align: right;" id="swap-usage">0%</span>
                            </div>
                            <span style="font-size: 9px; color: #777; margin-top: 2px;" id="swap-used-total">0 GB / 0 GB</span>
                        </div>
                    </div>
                </div>
                <div class="card-chart-area"><div class="chart-container"><canvas id="memory-chart"></canvas></div></div>
            </div>

            <!-- Disk Card -->
            <div class="card disk">
                <div class="card-header">
                    <div class="card-title">Disk</div>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <select id="disk-select"><option value="all">All Disks</option></select>
                        <div class="status-indicator" id="disk-status"></div>
                    </div>
                </div>
                <div class="card-content">
                    <div class="card-value" id="disk-usage">0%</div>
                    <div class="progress-container"><div class="progress-bar" id="disk-bar" style="width: 0%"></div></div>
                    <div class="card-stats-grid">
                        <div class="stat-box"><span class="stat-label">Disk Read</span><span class="stat-value" id="disk-read">0 B/s</span></div>
                        <div class="stat-box"><span class="stat-label">Disk Write</span><span class="stat-value" id="disk-write">0 B/s</span></div>
                        <div class="stat-box stat-full"><span class="stat-label">Capacity (Used/Total)</span><span class="stat-value" id="disk-used-total">0 GB / 0 GB</span></div>
                    </div>
                </div>
                <div class="card-chart-area"><div class="chart-container"><canvas id="disk-chart"></canvas></div></div>
            </div>

            <!-- Network Card -->
            <div class="card network">
                <div class="card-header">
                    <div class="card-title">Network</div>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <select id="network-interface-select"><option value="all">All Interfaces</option></select>
                        <div class="status-indicator" id="network-status"></div>
                    </div>
                </div>
                <div class="card-content">
                    <div class="card-value" id="network-total-io">0 B/s</div>
                    <div class="progress-container">
                        <div id="net-bar-rx" style="width: 50%; height: 100%; background: #4caf50; transition: width 0.3s ease;"></div>
                        <div id="net-bar-tx" style="width: 30%; height: 100%; background: #2196f3; transition: width 0.3s ease;"></div>
                    </div>
                    <div class="card-stats-grid">
                        <div class="stat-box"><span class="stat-label">Download</span><span class="stat-value text-good" id="network-rx">0 B/s</span></div>
                        <div class="stat-box"><span class="stat-label">Upload</span><span class="stat-value" style="color:#2196f3" id="network-tx">0 B/s</span></div>
                        <div class="stat-box"><span class="stat-label">Total In</span><span class="stat-value" id="network-total-rx">0 B</span></div>
                        <div class="stat-box"><span class="stat-label">Total Out</span><span class="stat-value" id="network-total-tx">0 B</span></div>
                    </div>
                </div>
                <div class="card-chart-area"><div class="chart-container"><canvas id="network-chart"></canvas></div></div>
            </div>

        </div>
        
        <!-- GPU cards on separate row/grid -->
        <div class="gpu-grid" id="gpu-grid">
            <div id="gpu-cards-container"></div>
        </div>

        <div class="grid-2col">
            <div class="card">
                <div class="card-header"><div class="card-title">Top Processes</div></div>
                <table class="processes-table">
                    <thead><tr><th>PID</th><th>Name</th><th class="cpu-cell">CPU%</th><th class="mem-cell">MEM%</th></tr></thead>
                    <tbody id="processes-body"></tbody>
                </table>
            </div>
            <div class="card">
                <div class="card-header"><div class="card-title">System Info</div></div>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-icon"><i class="fas fa-terminal"></i></div>
                        <div class="info-content">
                            <span class="info-label">OS Distro</span>
                            <span class="info-value" id="os-info">-</span>
                        </div>
                    </div>
                    <div class="info-item">
                        <div class="info-icon"><i class="fas fa-microchip"></i></div>
                        <div class="info-content">
                            <span class="info-label">Kernel</span>
                            <span class="info-value" id="kernel-info">-</span>
                        </div>
                    </div>
                    <div class="info-item">
                        <div class="info-icon"><i class="fas fa-clock"></i></div>
                        <div class="info-content">
                            <span class="info-label">Uptime</span>
                            <span class="info-value" id="uptime">-</span>
                        </div>
                    </div>
                    <div class="info-item">
                        <div class="info-icon"><i class="fas fa-tasks"></i></div>
                        <div class="info-content">
                            <span class="info-label">Load Avg (1/5/15)</span>
                            <span class="info-value" id="load-info">-</span>
                        </div>
                    </div>
                </div>
                <div class="nic-section">
                    <div class="nic-section-title"><i class="fas fa-network-wired" style="margin-right:8px"></i>Network Interfaces</div>
                    <div id="nic-list"></div>
                </div>
            </div>
        </div>

        <?php
            $configuredCentralHost = strtolower((string)(parse_url((string)($monitorConfig['central_url'] ?? ''), PHP_URL_HOST) ?: ''));
            $currentRequestHost = strtolower(preg_replace('/:\d+$/', '', (string)($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '')));
            $centralTargetsSelf = $configuredCentralHost !== ''
                && ($configuredCentralHost === $currentRequestHost || in_array($configuredCentralHost, ['127.0.0.1', 'localhost', '::1'], true));
            $agentStatusAge = time() - (int)($monitorAgentStatus['updated_at'] ?? 0);
            $agentStatusCurrent = $agentStatusAge >= 0 && $agentStatusAge <= 60;
            $agentFresh = $centralTargetsSelf || ($agentStatusCurrent && !empty($monitorAgentStatus['ok']));
            if ($centralTargetsSelf) {
                $agentMessage = 'This server';
            } elseif (!$agentStatusCurrent) {
                $agentMessage = empty($monitorConfig['central_url']) ? 'Not configured' : 'Waiting for Agent service';
            } else {
                $agentMessage = $monitorAgentStatus['message'] ?? 'Waiting for Agent service';
            }
        ?>
        <section class="card central-settings">
            <div class="card-header">
                <div class="card-title"><i class="fas fa-satellite-dish" style="margin-right:8px"></i>Central connection</div>
                <div class="agent-state"><span class="agent-state-dot<?php echo $agentFresh ? ' connected' : ''; ?>"></span><?php echo htmlspecialchars((string)$agentMessage, ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
            <?php if (is_array($monitorConfigMessage)): ?><div class="config-message <?php echo $monitorConfigMessage['type'] === 'success' ? 'success' : 'error'; ?>"><?php echo htmlspecialchars((string)$monitorConfigMessage['text'], ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?>
            <form class="central-form" method="post">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars((string)$_SESSION['monitor_csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="monitor_save_config" value="1">
                <div class="form-field"><label for="central-url">Central server</label><input id="central-url" name="central_url" value="<?php echo htmlspecialchars((string)$monitorConfig['central_url'], ENT_QUOTES, 'UTF-8'); ?>" placeholder="https://monitor.example.com"></div>
                <div class="form-field"><label for="node-id">Node name</label><input id="node-id" name="node_id" value="<?php echo htmlspecialchars((string)$monitorConfig['node_id'], ENT_QUOTES, 'UTF-8'); ?>" required></div>
                <div class="form-field"><label for="group-name">Group name</label><input id="group-name" name="group_name" maxlength="80" value="<?php echo htmlspecialchars((string)$monitorConfig['group_name'], ENT_QUOTES, 'UTF-8'); ?>" placeholder="Optional"></div>
                <div class="form-field"><label for="sample-interval">Seconds</label><input id="sample-interval" type="number" name="sample_interval" min="2" max="30" value="<?php echo (int)$monitorConfig['sample_interval']; ?>"></div>
                <button class="save-central" type="submit">Save</button>
            </form>
        </section>
    </div>

    <footer>
        <div class="footer-content">
            <div>&copy; 2019-<?php echo date("Y"); ?> <a href="https://linxi.com.au" target="_blank">linxi.com.au</a>. All Rights Reserved.</div>
            <div>Contact: <a href="mailto:linxi@linxi.com.au">linxi@linxi.com.au</a></div>
        </div>
    </footer>

    <script>
        const formatBytes = (bytes) => {
            if (bytes === 0) return '0 B';
            const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        };
        const formatGiBCompact = (bytes) => {
            const gb = bytes / (1024 ** 3);
            const txt = gb >= 10 ? gb.toFixed(1) : gb.toFixed(2);
            return txt.replace(/\.?0+$/, '') + 'GB';
        };

        const createChart = (id, color, label, max = 100, isBytes = false) => new Chart(document.getElementById(id).getContext('2d'), {
            type: 'line',
            data: { labels: Array(30).fill(''), datasets: [{ label, data: Array(30).fill(0), borderColor: color, backgroundColor: color + '1A', tension: 0.4, borderWidth: 2, pointRadius: 0 }] },
            options: {
                responsive: true, maintainAspectRatio: false, animation: false,
                plugins: { legend: { display: false } },
                scales: { 
                    x: { display: false }, 
                    y: { min: 0, max: max, ticks: { callback: v => isBytes ? formatBytes(v) : v + (max === 100 ? '%' : '') } } 
                }
            }
        });

        const memoryChart = createChart('memory-chart', '#2196f3', 'RAM', 16 * 1024**3, true);
        const diskChart = createChart('disk-chart', '#9c27b0', 'Disk');
        const networkChart = createChart('network-chart', '#4caf50', 'Net', 1024*1024, true);
        networkChart.data.datasets.push({ label: 'Up', data: Array(30).fill(0), borderColor: '#2196f3', backgroundColor: '#2196f31A', tension: 0.4, borderWidth: 2, pointRadius: 0 });
        const gpuCharts = new Map();
        const destroyGpuCharts = () => {
            gpuCharts.forEach((pair) => {
                try { if (pair.gpu) pair.gpu.destroy(); } catch (e) {}
                try { if (pair.vram) pair.vram.destroy(); } catch (e) {}
            });
            gpuCharts.clear();
        };
        const buildGpuCardHtml = (i) => `
            <div class="card gpu" id="gpu-card-${i}">
                <div class="card-header">
                    <div class="card-title"><span class="gpu-card-title" id="gpu-title-${i}">GPU</span></div>
                    <div class="status-indicator" id="gpu-status-${i}"></div>
                </div>
                <div class="card-content">
                    <div class="gpu-meters-row">
                        <div class="gpu-meter">
                            <div class="progress-label-row"><span>GPU</span><span class="gpu-meter-value" id="gpu-load-pct-${i}">0%</span></div>
                            <div class="progress-container"><div class="progress-bar gpu-load-bar" id="gpu-load-bar-${i}" style="width:0%"></div></div>
                        </div>
                        <div class="gpu-meter">
                            <div class="progress-label-row"><span>VRAM</span><span class="gpu-meter-value" id="gpu-vram-pct-${i}">0GB/0GB</span></div>
                            <div class="progress-container"><div class="progress-bar gpu-vram-bar" id="gpu-vram-bar-${i}" style="width:0%"></div></div>
                        </div>
                    </div>
                    <div class="card-stats-grid" id="gpu-stats-grid-${i}"></div>
                </div>
                <div class="card-chart-area">
                    <div class="gpu-charts-row">
                        <div class="gpu-chart-wrap">
                            <div class="gpu-chart-caption">GPU load</div>
                            <div class="chart-container"><canvas id="gpu-chart-${i}"></canvas></div>
                        </div>
                        <div class="gpu-chart-wrap">
                            <div class="gpu-chart-caption">VRAM</div>
                            <div class="chart-container"><canvas id="gpu-vram-chart-${i}"></canvas></div>
                        </div>
                    </div>
                </div>
            </div>`;

        const updateGpuSection = (gpuPayload) => {
            const container = document.getElementById('gpu-cards-container');
            const gpuGrid = document.getElementById('gpu-grid');
            const gpus = (gpuPayload && gpuPayload.gpus) ? gpuPayload.gpus : [];
            const visible = gpus.length > 0 && gpus[0].name && !String(gpus[0].name).includes('Unknown GPU');
            if (!visible) {
                gpuGrid.classList.remove('gpu-cards-visible');
                container.innerHTML = '';
                destroyGpuCharts();
                return;
            }
            gpuGrid.classList.add('gpu-cards-visible');
            if (container.children.length !== gpus.length) {
                container.innerHTML = '';
                destroyGpuCharts();
                const gpuLineOpts = (color, label) => ({
                    type: 'line',
                    data: { labels: Array(30).fill(''), datasets: [{ label, data: Array(30).fill(0), borderColor: color, backgroundColor: color + '1A', tension: 0.4, borderWidth: 2, pointRadius: 0 }] },
                    options: {
                        responsive: true, maintainAspectRatio: false, animation: false,
                        plugins: { legend: { display: false } },
                        scales: { x: { display: false }, y: { min: 0, max: 100, ticks: { callback: v => v + '%' } } }
                    }
                });
                const gpuVramLineOpts = () => ({
                    type: 'line',
                    data: { labels: Array(30).fill(''), datasets: [{ label: 'VRAM', data: Array(30).fill(0), borderColor: '#69f0ae', backgroundColor: '#69f0ae1A', tension: 0.4, borderWidth: 2, pointRadius: 0 }] },
                    options: {
                        responsive: true, maintainAspectRatio: false, animation: false,
                        plugins: { legend: { display: false } },
                        scales: { x: { display: false }, y: { min: 0, max: 8 * 1024 ** 3, ticks: { callback: v => formatBytes(v) } } }
                    }
                });
                gpus.forEach((g, i) => {
                    container.insertAdjacentHTML('beforeend', buildGpuCardHtml(i));
                    const ctxGpu = document.getElementById('gpu-chart-' + i).getContext('2d');
                    const ctxVram = document.getElementById('gpu-vram-chart-' + i).getContext('2d');
                    gpuCharts.set(i, {
                        gpu: new Chart(ctxGpu, gpuLineOpts('#00e676', 'GPU')),
                        vram: new Chart(ctxVram, gpuVramLineOpts())
                    });
                });
            }
            gpus.forEach((g, i) => {
                const grid = document.getElementById('gpu-stats-grid-' + i);
                const isNv = g.vendor === 'nvidia';
                if (grid && grid.dataset.built !== (isNv ? 'nv' : 'oth')) {
                    grid.dataset.built = isNv ? 'nv' : 'oth';
                    // NVIDIA: stats in 3 columns (rightmost columns are VRAM related)
                    if (isNv) grid.classList.add('gpu-nv-stats');
                    else grid.classList.remove('gpu-nv-stats');
                    if (isNv) {
                        grid.innerHTML = `
                            <div class="stat-box"><span class="stat-label">Temp</span><span class="stat-value" id="gpu-temp-${i}">--°C</span></div>
                            <div class="stat-box"><span class="stat-label">Clock</span><span class="stat-value" id="gpu-clock-${i}">-- MHz</span></div>
                            <div class="stat-box"><span class="stat-label">VRAM</span><span class="stat-value" id="gpu-vram-detail-${i}">--</span></div>
                            <div class="stat-box"><span class="stat-label">Power</span><span class="stat-value" id="gpu-power-${i}">--</span></div>
                            <div class="stat-box"><span class="stat-label">Throttling reason</span><span class="stat-value" id="gpu-limit-${i}">--</span></div>`;
                        // Note: memory controller utilization must be the rightmost item per row (3-column grid)
                        grid.innerHTML += `
                            <div class="stat-box"><span class="stat-label">VRAM Ctrl Util</span><span class="stat-value" id="gpu-mem-ctrl-${i}">--%</span></div>`;
                    } else {
                        grid.innerHTML = `
                            <div class="stat-box"><span class="stat-label">Frequency</span><span class="stat-value" id="gpu-freq-${i}">-- MHz</span></div>
                            <div class="stat-box"><span class="stat-label">Temp</span><span class="stat-value" id="gpu-temp-${i}">--°C</span></div>
                            <div class="stat-box stat-full"><span class="stat-label">VRAM</span><span class="stat-value" id="gpu-vram-detail-${i}">--</span></div>`;
                    }
                }
                const gpuIdx = (g.index !== undefined && g.index !== null) ? g.index : i;
                const rawGpuName = String(g.name || 'GPU').trim();
                document.getElementById('gpu-title-' + i).textContent = 'GPU' + gpuIdx + ' · ' + rawGpuName;
                if (g.available === false) {
                    document.getElementById('gpu-load-pct-' + i).textContent = 'N/A';
                    document.getElementById('gpu-load-bar-' + i).style.width = '0%';
                    document.getElementById('gpu-vram-pct-' + i).textContent = '--/--';
                    document.getElementById('gpu-vram-bar-' + i).style.width = '0%';
                    const powerNA = document.getElementById('gpu-power-' + i);
                    if (powerNA) powerNA.textContent = '--';
                    const limitNA = document.getElementById('gpu-limit-' + i);
                    if (limitNA) limitNA.textContent = '--';
                    const memCtrlNA = document.getElementById('gpu-mem-ctrl-' + i);
                    if (memCtrlNA) memCtrlNA.textContent = '--';
                    document.getElementById('gpu-status-' + i).className = 'status-indicator status-warning';
                    return;
                }
                const loadPct = Math.round(g.usage != null ? g.usage : 0);
                const vramPct = Math.round(g.memory_used_pct != null ? g.memory_used_pct : 0);
                document.getElementById('gpu-load-pct-' + i).textContent = loadPct + '%';
                updateTextStatus(document.getElementById('gpu-load-pct-' + i), loadPct);
                document.getElementById('gpu-load-bar-' + i).style.width = Math.min(100, loadPct) + '%';
                const vramUsed = (g.memory && g.memory.used) ? g.memory.used : 0;
                const vramTotal = (g.memory && g.memory.total) ? g.memory.total : 0;
                document.getElementById('gpu-vram-pct-' + i).textContent = vramTotal > 0 ? (formatGiBCompact(vramUsed) + '/' + formatGiBCompact(vramTotal)) : '--/--';
                document.getElementById('gpu-vram-bar-' + i).style.width = Math.min(100, vramPct) + '%';
                const vramDetail = (g.memory && g.memory.total > 0)
                    ? formatBytes(g.memory.used) + ' / ' + formatBytes(g.memory.total)
                    : '--';
                const tEl = document.getElementById('gpu-temp-' + i);
                if (tEl) tEl.textContent = g.temp > 0 ? Math.round(g.temp) + '°C' : '--°C';
                const vd = document.getElementById('gpu-vram-detail-' + i);
                if (vd) vd.textContent = vramDetail;
                if (isNv) {
                    const clk = document.getElementById('gpu-clock-' + i);
                    if (clk) clk.textContent = (g.freq > 0) ? (g.freq + ' MHz') : '-- MHz';
                    const pwrEl = document.getElementById('gpu-power-' + i);
                    if (pwrEl) {
                        const pd = g.power_draw;
                        const pc = g.power_cap;
                        if (pd != null && pc != null && pc > 0) {
                            pwrEl.textContent = `${pd.toFixed(0)}/${pc.toFixed(0)} W`;
                        } else if (pd != null) {
                            pwrEl.textContent = `${pd.toFixed(0)} W`;
                        } else {
                            pwrEl.textContent = '--';
                        }
                    }
                    const limitEl = document.getElementById('gpu-limit-' + i);
                    if (limitEl) {
                        limitEl.textContent = g.limit_reason ? g.limit_reason : '--';
                    }
                    const memCtrlEl = document.getElementById('gpu-mem-ctrl-' + i);
                    if (memCtrlEl) {
                        const mc = g.memory_utilization;
                        if (mc !== null && mc !== undefined) memCtrlEl.textContent = Math.round(mc) + '%';
                        else memCtrlEl.textContent = '--%';
                    }
                } else {
                    const fq = document.getElementById('gpu-freq-' + i);
                    if (fq) {
                        if (g.freq_info) fq.textContent = g.freq_info;
                        else if (g.freq) fq.textContent = g.freq + ' MHz';
                        else fq.textContent = '-- MHz';
                    }
                }
                const statusPct = Math.max(loadPct, vramPct);
                updateStatus('gpu-status-' + i, statusPct);
                const pair = gpuCharts.get(i);
                if (pair && pair.gpu && pair.vram) {
                    pair.gpu.data.datasets[0].data.shift();
                    pair.gpu.data.datasets[0].data.push(loadPct);
                    pair.gpu.update('none');
                    pair.vram.data.datasets[0].data.shift();
                    pair.vram.data.datasets[0].data.push(vramUsed);
                    pair.vram.options.scales.y.max = Math.max(vramTotal || 0, ...pair.vram.data.datasets[0].data, 1) * 1.1;
                    pair.vram.update('none');
                }
            });
        };

        let selectedIface = 'all';
        document.getElementById('network-interface-select').onchange = e => selectedIface = e.target.value;

        let selectedDisk = 'all';
        document.getElementById('disk-select').onchange = e => selectedDisk = e.target.value;

        const cpuCharts = new Map();
        const coreChartsBySocket = new Map();
        const destroyCpuCharts = () => {
            cpuCharts.forEach((ch) => { try { ch.destroy(); } catch (e) {} });
            cpuCharts.clear();
            coreChartsBySocket.forEach((sub) => {
                Object.values(sub).forEach((ch) => { try { ch.destroy(); } catch (e) {} });
            });
            coreChartsBySocket.clear();
        };

        const buildCpuCardHtml = (i) => `
            <div class="card cpu" id="cpu-card-${i}">
                <div class="card-header">
                    <div class="card-title"><span id="cpu-title-${i}">CPU</span></div>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <button type="button" class="toggle-btn cpu-toggle" data-socket="${i}" id="cpu-toggle-${i}">Per-Core</button>
                        <div class="status-indicator" id="cpu-status-${i}"></div>
                    </div>
                </div>
                <div class="card-content">
                    <div class="card-value" id="cpu-usage-${i}">0%</div>
                    <div class="progress-container"><div class="progress-bar" id="cpu-bar-${i}" style="width: 0%"></div></div>
                    <div class="card-stats-grid">
                        <div class="stat-box"><span class="stat-label">Cores</span><span class="stat-value" id="cpu-cores-${i}">0</span></div>
                        <div class="stat-box"><span class="stat-label">Temp</span><span class="stat-value" id="cpu-temp-${i}">--°C</span></div>
                        <div class="stat-box stat-full"><span class="stat-label">Model</span><span class="stat-value" id="cpu-model-${i}">-</span></div>
                    </div>
                </div>
                <div class="card-chart-area">
                    <div id="cpu-chart-container-${i}" class="chart-container"><canvas id="cpu-chart-${i}"></canvas></div>
                    <div id="cpu-percore-container-${i}" class="cpu-percore-container" style="display: none;"></div>
                </div>
            </div>`;

        const updatePerCoreForSocket = (socketIdx, cores) => {
            const container = document.getElementById('cpu-percore-container-' + socketIdx);
            if (!container) return;
            const key = 's' + socketIdx;
            let sub = coreChartsBySocket.get(key) || {};
            if (container.children.length !== cores.length) {
                container.innerHTML = '';
                Object.values(sub).forEach((ch) => { try { ch.destroy(); } catch (e) {} });
                sub = {};
                cores.forEach((c, i) => {
                    const cid = 'core-' + socketIdx + '-' + i;
                    const div = document.createElement('div');
                    div.className = 'core-chart-container';
                    div.innerHTML = `<div class="core-chart-label">Core ${i}: 0%</div><canvas id="${cid}"></canvas>`;
                    container.appendChild(div);
                    sub[i] = new Chart(document.getElementById(cid).getContext('2d'), {
                        type: 'line',
                        data: { labels: Array(20).fill(''), datasets: [{ data: Array(20).fill(0), borderColor: '#ff9800', borderWidth: 1, pointRadius: 0, fill: true, backgroundColor: '#ff98001A' }] },
                        options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: false }, scales: { x: { display: false }, y: { min: 0, max: 100, display: false } } }
                    });
                });
                coreChartsBySocket.set(key, sub);
            }
            sub = coreChartsBySocket.get(key);
            cores.forEach((c, i) => {
                const val = Math.round(c.load);
                const chart = sub[i];
                if (!chart) return;
                chart.data.datasets[0].data.shift();
                chart.data.datasets[0].data.push(val);
                chart.update('none');
                const canvas = document.getElementById('core-' + socketIdx + '-' + i);
                if (canvas && canvas.previousSibling) canvas.previousSibling.textContent = `Core ${i}: ${val}%`;
            });
        };

        const updateCpuSection = (cpuPayload) => {
            const container = document.getElementById('cpu-cards-container');
            let pkgs = (cpuPayload && cpuPayload.packages && cpuPayload.packages.length) ? cpuPayload.packages : [];
            if (pkgs.length === 0 && cpuPayload) {
                pkgs = [{
                    index: 0,
                    usage: cpuPayload.usage,
                    cores: cpuPayload.cores,
                    temp: cpuPayload.temp,
                    model: cpuPayload.model,
                    perCore: cpuPayload.perCore || []
                }];
            }
            if (pkgs.length === 0) {
                container.innerHTML = '';
                destroyCpuCharts();
                return;
            }
            if (container.children.length !== pkgs.length) {
                container.innerHTML = '';
                destroyCpuCharts();
                pkgs.forEach((p, i) => {
                    container.insertAdjacentHTML('beforeend', buildCpuCardHtml(i));
                    const ctx = document.getElementById('cpu-chart-' + i).getContext('2d');
                    cpuCharts.set(i, new Chart(ctx, {
                        type: 'line',
                        data: { labels: Array(30).fill(''), datasets: [{ label: 'CPU', data: Array(30).fill(0), borderColor: '#ff9800', backgroundColor: '#ff98001A', tension: 0.4, borderWidth: 2, pointRadius: 0 }] },
                        options: {
                            responsive: true, maintainAspectRatio: false, animation: false,
                            plugins: { legend: { display: false } },
                            scales: { x: { display: false }, y: { min: 0, max: 100, ticks: { callback: v => v + '%' } } }
                        }
                    }));
                });
            }
            pkgs.forEach((p, i) => {
                const pkgIdx = (p.index !== undefined && p.index !== null) ? p.index : i;
                const titleModel = String(p.model || cpuPayload.model || '').trim() || 'Unknown';
                document.getElementById('cpu-title-' + i).textContent = 'CPU' + pkgIdx;
                const cpuVal = Math.round(p.usage != null ? p.usage : 0);
                const cpuUsageEl = document.getElementById('cpu-usage-' + i);
                cpuUsageEl.textContent = cpuVal + '%';
                updateTextStatus(cpuUsageEl, cpuVal);
                document.getElementById('cpu-bar-' + i).style.width = cpuVal + '%';
                document.getElementById('cpu-cores-' + i).textContent = p.cores != null ? p.cores : 0;
                document.getElementById('cpu-model-' + i).textContent = titleModel;
                const t = p.temp;
                const tempEl = document.getElementById('cpu-temp-' + i);
                if (t > 0) {
                    tempEl.textContent = Math.round(t) + '°C';
                    tempEl.style.color = t > 75 ? '#f44336' : (t > 60 ? '#ff9800' : '#4caf50');
                } else {
                    tempEl.textContent = '--°C';
                    tempEl.style.color = '';
                }
                updateStatus('cpu-status-' + i, cpuVal);
                const ch = cpuCharts.get(i);
                if (ch) {
                    ch.data.datasets[0].data.shift();
                    ch.data.datasets[0].data.push(cpuVal);
                    ch.update('none');
                }
                updatePerCoreForSocket(i, p.perCore || []);
            });
        };

        document.getElementById('cpu-cards-container').addEventListener('click', (e) => {
            const btn = e.target.closest('.cpu-toggle');
            if (!btn) return;
            const i = btn.dataset.socket;
            const chartCont = document.getElementById('cpu-chart-container-' + i);
            const perCont = document.getElementById('cpu-percore-container-' + i);
            if (!chartCont || !perCont) return;
            const isPC = perCont.style.display === 'none';
            perCont.style.display = isPC ? 'grid' : 'none';
            chartCont.style.display = isPC ? 'none' : 'block';
            btn.classList.toggle('active', isPC);
        });

        const statusEl = document.getElementById('connection-status');
        const remoteNode = <?php echo json_encode($monitorRemoteNode, JSON_UNESCAPED_SLASHES); ?>;
        const streamUrl = remoteNode ? ('?monitor_api=remote_stream&node=' + encodeURIComponent(remoteNode)) : '?stream=1';
        const evtSource = new EventSource(streamUrl);

        if (remoteNode) {
            statusEl.style.display = 'block';
            statusEl.style.background = '#1d4050';
            statusEl.textContent = 'Requesting live detail from ' + remoteNode + '...';
        }

        evtSource.onopen = () => {
            if (!remoteNode) statusEl.style.display = 'none';
        };

        const updateStatus = (id, percentage) => {
            const el = document.getElementById(id);
            if (!el) return;
            el.classList.remove('status-good', 'status-warning', 'status-critical');
            if (percentage < 70) el.classList.add('status-good');
            else if (percentage < 90) el.classList.add('status-warning');
            else el.classList.add('status-critical');
        };

        const updateTextStatus = (el, percentage) => {
            el.classList.remove('text-good', 'text-warning', 'text-critical');
            if (percentage < 70) el.classList.add('text-good');
            else if (percentage < 90) el.classList.add('text-warning');
            else el.classList.add('text-critical');
        };

        evtSource.onmessage = e => {
            statusEl.style.display = 'none';
            const d = JSON.parse(e.data);
            document.getElementById('current-time').textContent = new Date(d.timestamp).toLocaleTimeString();
            if (d.system && d.system.host) {
                const baseTitle = 'Server Resource Monitor';
                const hostSuffix = ' - ' + d.system.host;
                document.title = baseTitle + hostSuffix;
                const h1 = document.getElementById('page-title');
                if (h1) {
                    h1.innerHTML = '<i class=\"fas fa-chart-line\"></i> ' + baseTitle + hostSuffix;
                }
            }
            
            // CPU (one card per physical socket)
            updateCpuSection(d.cpu);

            // Memory & Swap
            const memPerc = Math.round(d.memory.percentage);
            const memUsageEl = document.getElementById('memory-usage');
            memUsageEl.textContent = memPerc + '%';
            updateTextStatus(memUsageEl, memPerc);
            document.getElementById('memory-bar').style.width = memPerc + '%';
            document.getElementById('memory-total').textContent = formatBytes(d.memory.total);
            document.getElementById('memory-used').textContent = formatBytes(d.memory.used);
            
            // Memory Speed
            if (d.memory.speed !== null && d.memory.speed !== undefined) {
                document.getElementById('memory-speed').textContent = d.memory.speed + ' MHz';
            } else {
                document.getElementById('memory-speed').textContent = '-- MHz';
            }
            
            const swapPerc = Math.round(d.memory.swapPercentage);
            document.getElementById('swap-usage').textContent = swapPerc + '%';
            document.getElementById('swap-bar').style.width = swapPerc + '%';
            document.getElementById('swap-used-total').textContent = `${formatBytes(d.memory.swapUsed)} / ${formatBytes(d.memory.swapTotal)}`;

            updateStatus('memory-status', Math.max(memPerc, swapPerc));
            memoryChart.options.scales.y.max = d.memory.total;
            memoryChart.data.datasets[0].data.shift();
            memoryChart.data.datasets[0].data.push(d.memory.used);
            memoryChart.update('none');

            // Disk
            const diskSel = document.getElementById('disk-select');
            if (diskSel.options.length <= 1 && d.disk_io.perDisk) {
                Object.keys(d.disk_io.perDisk).forEach(dev => {
                    const o = document.createElement('option');
                    o.value = dev;
                    o.textContent = dev;
                    diskSel.appendChild(o);
                });
            }

            let totalD = 0, usedD = 0;
            d.disk.forEach(disk => { totalD += disk.size; usedD += disk.used; });
            const diskPerc = totalD > 0 ? Math.round((usedD / totalD) * 100) : 0;
            const diskUsageEl = document.getElementById('disk-usage');
            diskUsageEl.textContent = diskPerc + '%';
            updateTextStatus(diskUsageEl, diskPerc);
            document.getElementById('disk-bar').style.width = diskPerc + '%';
            document.getElementById('disk-used-total').textContent = `${formatBytes(usedD)} / ${formatBytes(totalD)}`;

            let diskR = d.disk_io.r, diskW = d.disk_io.w;
            if (selectedDisk !== 'all' && d.disk_io.perDisk[selectedDisk]) {
                diskR = d.disk_io.perDisk[selectedDisk].r;
                diskW = d.disk_io.perDisk[selectedDisk].w;
            }
            document.getElementById('disk-read').textContent = formatBytes(diskR) + '/s';
            document.getElementById('disk-write').textContent = formatBytes(diskW) + '/s';

            updateStatus('disk-status', diskPerc);
            diskChart.data.datasets[0].data.shift();
            diskChart.data.datasets[0].data.push(diskPerc);
            diskChart.update('none');

            // Network
            const sel = document.getElementById('network-interface-select');
            if (sel.options.length <= 1) {
                d.network.forEach(n => { const o = document.createElement('option'); o.value = n.interface; o.textContent = n.interface; sel.appendChild(o); });
            }
            let rx = 0, tx = 0, tr = 0, tt = 0;
            if (selectedIface === 'all') {
                rx = d.networkHistory.download; tx = d.networkHistory.upload;
                d.network.forEach(n => { tr += n.rxTotal; tt += n.txTotal; });
            } else {
                const n = d.network.find(i => i.interface === selectedIface);
                if (n) { rx = n.rx_speed; tx = n.tx_speed; tr = n.rxTotal; tt = n.txTotal; }
            }
            document.getElementById('network-total-io').textContent = formatBytes(rx + tx) + '/s';
            document.getElementById('network-rx').textContent = formatBytes(rx) + '/s';
            document.getElementById('network-tx').textContent = formatBytes(tx) + '/s';
            document.getElementById('network-total-rx').textContent = formatBytes(tr);
            document.getElementById('network-total-tx').textContent = formatBytes(tt);
            
            // Network split bar logic
            const totalIO = rx + tx;
            if (totalIO > 0) {
                document.getElementById('net-bar-rx').style.width = (rx / totalIO * 100) + '%';
                document.getElementById('net-bar-tx').style.width = (tx / totalIO * 100) + '%';
            } else {
                document.getElementById('net-bar-rx').style.width = '0%';
                document.getElementById('net-bar-tx').style.width = '0%';
            }

            networkChart.data.datasets[0].data.shift(); networkChart.data.datasets[0].data.push(rx);
            networkChart.data.datasets[1].data.shift(); networkChart.data.datasets[1].data.push(tx);
            const maxNet = Math.max(...networkChart.data.datasets[0].data, ...networkChart.data.datasets[1].data);
            networkChart.options.scales.y.max = Math.max(1024*1024, maxNet * 1.2);
            networkChart.update('none');

            // GPU (multi-card: d.gpu.gpus[])
            updateGpuSection(d.gpu);

            // Processes
            document.getElementById('processes-body').innerHTML = d.processes.map(p => `<tr><td>${p.pid}</td><td>${p.name}</td><td class="cpu-cell">${p.cpu}%</td><td class="mem-cell">${p.mem}%</td></tr>`).join('');

            // Info
            document.getElementById('os-info').textContent = d.system.os.distro;
            document.getElementById('kernel-info').textContent = d.system.os.release;
            const up = d.system.uptime;
            document.getElementById('uptime').textContent = `${Math.floor(up/86400)}d ${Math.floor((up%86400)/3600)}h ${Math.floor((up%3600)/60)}m`;
            document.getElementById('load-info').textContent = d.system.load.join(' / ');

            // NICs
            const nicList = document.getElementById('nic-list');
            if (d.system.network && d.system.network.interfaces) {
                nicList.innerHTML = d.system.network.interfaces.map(nic => `
                    <div class="nic-item">
                        <span class="nic-name"><i class="fas fa-microchip" style="margin-right:8px; font-size:10px; color: #4fc3f7"></i>${nic.interface}</span>
                        <span class="nic-ip">${nic.ip}</span>
                    </div>
                `).join('');
            }
        };

        evtSource.onerror = () => {
            statusEl.style.display = 'block';
            statusEl.className = 'error';
            statusEl.textContent = 'Connection lost. Reconnecting...';
        };

    </script>
</body>
</html>
