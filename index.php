<?php
/**
 * Server Resource Monitor - Single File PHP Version
 * Targeted for Linux Platform
 */

// --- Password Protection ---
session_start();
$PROTECTED_PASSWORD = "admin888"; // CHANGE THIS PASSWORD

if (!isset($_SESSION['authenticated'])) {
    if (isset($_POST['password']) && $_POST['password'] === $PROTECTED_PASSWORD) {
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

// --- Backend Logic ---

if (isset($_GET['stream'])) {
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no'); // Disable buffering for Nginx

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

        // Calculate real-time CPU usage from /proc/[pid]/stat
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

        // First reading
        $prev_proc = $read_proc_cpu($proc_pids);
        $prev_time_proc = microtime(true);
        usleep(200000); // 200ms delay

        // Second reading
        $curr_proc = $read_proc_cpu($proc_pids);
        $curr_time_proc = microtime(true);
        $proc_interval = $curr_time_proc - $prev_time_proc;

        // Calculate CPU usage delta for each process
        if ($proc_interval > 0) {
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
        $nvidia_csv = shell_exec('nvidia-smi --query-gpu=index,name,utilization.gpu,utilization.memory,memory.total,memory.used,temperature.gpu,clocks.current.graphics --format=csv,noheader,nounits 2>/dev/null');
        if ($nvidia_csv !== null && trim($nvidia_csv) !== '') {
            foreach (explode("\n", trim($nvidia_csv)) as $line) {
                if ($line === '') {
                    continue;
                }
                $p = str_getcsv($line);
                if (count($p) < 8) {
                    continue;
                }
                $mem_total_mib = (float)trim($p[4]);
                $mem_used_mib = (float)trim($p[5]);
                $mem_total_bytes = (int)round($mem_total_mib * 1024 * 1024);
                $mem_used_bytes = (int)round($mem_used_mib * 1024 * 1024);
                $mem_used_pct = $mem_total_mib > 0 ? (int)round($mem_used_mib / $mem_total_mib * 100) : 0;
                $temp_raw = trim($p[6]);
                $freq_raw = trim($p[7]);
                $temp = preg_match('/^[\d.]+$/', $temp_raw) ? (float)$temp_raw : 0;
                $freq = preg_match('/^[\d.]+$/', $freq_raw) ? (int)$freq_raw : 0;
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
            $xpu = shell_exec('xpu-smi stats --json 2>/dev/null');
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
                'network' => ['interfaces' => $ips]
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Resource Monitor</title>
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
        #cpu-cards-container { display: contents; }
        #gpu-cards-container { display: none; }
        #gpu-cards-container.gpu-cards-visible { display: contents; }
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
        .cpu-percore-container { margin-top: 10px; display: grid; grid-template-columns: repeat(auto-fill, minmax(80px, 1fr)); gap: 8px; max-height: 200px; overflow-y: auto; }
        .core-chart-container { height: 60px; position: relative; border: 1px solid #333; border-radius: 4px; }
        .core-chart-label { position: absolute; top: 1px; left: 3px; font-size: 9px; color: #bbb; z-index: 10; font-weight: 500; }
        .network-stats-row { display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 14px; }
        #network-interface-select { background: #333; color: #e0e0e0; border: 1px solid #555; border-radius: 4px; padding: 4px 8px; font-size: 12px; }
        #disk-select { background: #333; color: #e0e0e0; border: 1px solid #555; border-radius: 4px; padding: 4px 8px; font-size: 12px; }
        #connection-status { padding: 5px 10px; border-radius: 4px; font-size: 12px; margin-bottom: 10px; display: none; text-align: center; }
        .error { background: #f44336; color: white; }
        
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
            .grid-2col { display: flex; flex-direction: column; }
            .info-grid { grid-template-columns: 1fr; }
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
            <h1><i class="fas fa-chart-line"></i> Server Resource Monitor</h1>
            <div class="timestamp" id="current-time">Connecting...</div>
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

            <!-- GPU cards (one per device; populated by JS) -->
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
                            <div class="progress-label-row"><span>GPU</span><span id="gpu-load-pct-${i}">0%</span></div>
                            <div class="progress-container"><div class="progress-bar gpu-load-bar" id="gpu-load-bar-${i}" style="width:0%"></div></div>
                        </div>
                        <div class="gpu-meter">
                            <div class="progress-label-row"><span>VRAM</span><span id="gpu-vram-pct-${i}">0%</span></div>
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
            const gpus = (gpuPayload && gpuPayload.gpus) ? gpuPayload.gpus : [];
            const visible = gpus.length > 0 && gpus[0].name && !String(gpus[0].name).includes('Unknown GPU');
            if (!visible) {
                container.classList.remove('gpu-cards-visible');
                container.innerHTML = '';
                destroyGpuCharts();
                return;
            }
            container.classList.add('gpu-cards-visible');
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
                gpus.forEach((g, i) => {
                    container.insertAdjacentHTML('beforeend', buildGpuCardHtml(i));
                    const ctxGpu = document.getElementById('gpu-chart-' + i).getContext('2d');
                    const ctxVram = document.getElementById('gpu-vram-chart-' + i).getContext('2d');
                    gpuCharts.set(i, {
                        gpu: new Chart(ctxGpu, gpuLineOpts('#00e676', 'GPU')),
                        vram: new Chart(ctxVram, gpuLineOpts('#69f0ae', 'VRAM'))
                    });
                });
            }
            gpus.forEach((g, i) => {
                const grid = document.getElementById('gpu-stats-grid-' + i);
                const isNv = g.vendor === 'nvidia';
                if (grid && grid.dataset.built !== (isNv ? 'nv' : 'oth')) {
                    grid.dataset.built = isNv ? 'nv' : 'oth';
                    if (isNv) {
                        grid.innerHTML = `
                            <div class="stat-box"><span class="stat-label">Temp</span><span class="stat-value" id="gpu-temp-${i}">--°C</span></div>
                            <div class="stat-box"><span class="stat-label">Clock</span><span class="stat-value" id="gpu-clock-${i}">-- MHz</span></div>
                            <div class="stat-box"><span class="stat-label">VRAM</span><span class="stat-value" id="gpu-vram-detail-${i}">--</span></div>
                            <div class="stat-box"><span class="stat-label">VRAM controller</span><span class="stat-value" id="gpu-mem-ctrl-${i}">--%</span></div>`;
                    } else {
                        grid.innerHTML = `
                            <div class="stat-box"><span class="stat-label">Frequency</span><span class="stat-value" id="gpu-freq-${i}">-- MHz</span></div>
                            <div class="stat-box"><span class="stat-label">Temp</span><span class="stat-value" id="gpu-temp-${i}">--°C</span></div>
                            <div class="stat-box stat-full"><span class="stat-label">VRAM</span><span class="stat-value" id="gpu-vram-detail-${i}">--</span></div>`;
                    }
                }
                const gpuIdx = (g.index !== undefined && g.index !== null) ? g.index : i;
                const gpuTitleName = String(g.name || '').replace(/^GPU:\s*/i, '').trim() || 'Unknown';
                document.getElementById('gpu-title-' + i).textContent = 'GPU' + gpuIdx + ' · ' + gpuTitleName;
                if (g.available === false) {
                    document.getElementById('gpu-load-pct-' + i).textContent = 'N/A';
                    document.getElementById('gpu-load-bar-' + i).style.width = '0%';
                    document.getElementById('gpu-vram-pct-' + i).textContent = 'N/A';
                    document.getElementById('gpu-vram-bar-' + i).style.width = '0%';
                    document.getElementById('gpu-status-' + i).className = 'status-indicator status-warning';
                    return;
                }
                const loadPct = Math.round(g.usage != null ? g.usage : 0);
                const vramPct = Math.round(g.memory_used_pct != null ? g.memory_used_pct : 0);
                document.getElementById('gpu-load-pct-' + i).textContent = loadPct + '%';
                updateTextStatus(document.getElementById('gpu-load-pct-' + i), loadPct);
                document.getElementById('gpu-load-bar-' + i).style.width = Math.min(100, loadPct) + '%';
                document.getElementById('gpu-vram-pct-' + i).textContent = vramPct + '%';
                updateTextStatus(document.getElementById('gpu-vram-pct-' + i), vramPct);
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
                    const mc = document.getElementById('gpu-mem-ctrl-' + i);
                    if (mc && g.memory_utilization != null) mc.textContent = Math.round(g.memory_utilization) + '%';
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
                    pair.vram.data.datasets[0].data.push(vramPct);
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
        const evtSource = new EventSource("?stream=1");

        evtSource.onopen = () => {
            statusEl.style.display = 'none';
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
