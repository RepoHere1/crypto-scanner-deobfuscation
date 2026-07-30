#!/usr/bin/env python3
"""
Adaptive Throttling System for Crypto Scanner

Implements intelligent rate limiting that adapts to platform responses,
respects rate limits, and rotates through platforms to avoid detection.
"""

import os
import subprocess
import sys
import time
import signal
import json
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional


# Lower CPU/nice priority to stay nice to system
os.nice(19)

HOME = os.path.expanduser("~")
PID_DIR = os.path.join(HOME, ".run_pids")
PID_FILE = os.path.join(PID_DIR, "adaptive_scan.pid")
os.makedirs(PID_DIR, exist_ok=True)

# Configuration for adaptive throttling
ADAPTIVE_CONFIG = os.path.join(HOME, ".adaptive_config.json")

class AdaptiveThrottler:
    def __init__(self):
        self.scan_stats = {}
        self.platform_configs = {}
        self.load_config()
        self.write_pid()
    
    def write_pid(self):
        """Write PID file"""
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
    
    def load_config(self):
        """Load adaptive configuration from file"""
        try:
            with open(ADAPTIVE_CONFIG, 'r') as f:
                config = json.load(f)
                self.scan_stats = config.get('scan_stats', {})
                self.platform_configs = config.get('platform_configs', {
                    'github': {'base_delay': 1.0, 'max_delay': 10.0, 'error_count': 0},
                    'gitlab': {'base_delay': 1.5, 'max_delay': 15.0, 'error_count': 0},
                    'huggingface': {'base_delay': 2.0, 'max_delay': 20.0, 'error_count': 0},
                    'docker': {'base_delay': 1.0, 'max_delay': 10.0, 'error_count': 0},
                    'circleci': {'base_delay': 1.0, 'max_delay': 8.0, 'error_count': 0},
                    'postman': {'base_delay': 1.5, 'max_delay': 12.0, 'error_count': 0},
                    'aws_s3': {'base_delay': 0.5, 'max_delay': 5.0, 'error_count': 0},
                    'gcs': {'base_delay': 0.8, 'max_delay': 8.0, 'error_count': 0},
                    'jenkins': {'base_delay': 2.0, 'max_delay': 20.0, 'error_count': 0},
                    'elasticsearch': {'base_delay': 1.2, 'max_delay': 12.0, 'error_count': 0},
                    'syslog': {'base_delay': 1.0, 'max_delay': 10.0, 'error_count': 0},
                })
        except FileNotFoundError:
            # Initialize default configuration
            self.scan_stats = {}
            self.platform_configs = {
                'github': {'base_delay': 1.0, 'max_delay': 10.0, 'error_count': 0},
                'gitlab': {'base_delay': 1.5, 'max_delay': 15.0, 'error_count': 0},
                'huggingface': {'base_delay': 2.0, 'max_delay': 20.0, 'error_count': 0},
                'docker': {'base_delay': 1.0, 'max_delay': 10.0, 'error_count': 0},
                'circleci': {'base_delay': 1.0, 'max_delay': 8.0, 'error_count': 0},
                'postman': {'base_delay': 1.5, 'max_delay': 12.0, 'error_count': 0},
                'aws_s3': {'base_delay': 0.5, 'max_delay': 5.0, 'error_count': 0},
                'gcs': {'base_delay': 0.8, 'max_delay': 8.0, 'error_count': 0},
                'jenkins': {'base_delay': 2.0, 'max_delay': 20.0, 'error_count': 0},
                'elasticsearch': {'base_delay': 1.2, 'max_delay': 12.0, 'error_count': 0},
                'syslog': {'base_delay': 1.0, 'max_delay': 10.0, 'error_count': 0},
            }
    
    def save_config(self):
        """Save adaptive configuration to file"""
        config = {
            'scan_stats': self.scan_stats,
            'platform_configs': self.platform_configs
        }
        with open(ADAPTIVE_CONFIG, 'w') as f:
            json.dump(config, f, indent=2)
    
    def detect_platform_from_url(self, url: str) -> str:
        """Detect platform from URL"""
        url_lower = url.lower()
        if 'github.com' in url_lower:
            return 'github'
        elif 'gitlab.com' in url_lower:
            return 'gitlab'
        elif 'huggingface.co' in url_lower:
            return 'huggingface'
        elif 'docker.io' in url_lower or 'registry.hub.docker.com' in url_lower:
            return 'docker'
        elif 'circleci.com' in url_lower:
            return 'circleci'
        elif 'postman.com' in url_lower:
            return 'postman'
        elif 'amazonaws.com' in url_lower and ('s3' in url_lower or 'bucket' in url_lower):
            return 'aws_s3'
        elif 'googleapis.com' in url_lower and 'storage' in url_lower:
            return 'gcs'
        elif 'jenkins' in url_lower:
            return 'jenkins'
        elif 'elasticsearch' in url_lower or 'es' in url_lower:
            return 'elasticsearch'
        else:
            return 'unknown'
    
    def get_adaptive_delay(self, platform: str, response_code: int = 200, error_occurred: bool = False) -> float:
        """Calculate adaptive delay based on platform and recent responses"""
        # Ensure the platform exists in configs, default to github if unknown
        if platform not in self.platform_configs:
            # Add the unknown platform with default values
            self.platform_configs[platform] = {
                'base_delay': 1.0,
                'max_delay': 10.0,
                'error_count': 0
            }
        
        config = self.platform_configs[platform]
        
        base_delay = config['base_delay']
        current_error_count = config['error_count']
        
        # Adjust delay based on recent errors
        if error_occurred or response_code >= 400:
            current_error_count += 1
            # Exponential backoff for errors
            delay = min(base_delay * (1.5 ** current_error_count), config['max_delay'])
        else:
            # Reduce error count gradually when successful
            current_error_count = max(0, current_error_count - 0.1)
            delay = base_delay * (1.1 ** current_error_count)
        
        # Update error count in config
        self.platform_configs[platform]['error_count'] = current_error_count
        
        return delay
    
    def update_scan_stats(self, platform: str, success: bool, response_time: float):
        """Update statistics for the platform"""
        if platform not in self.scan_stats:
            self.scan_stats[platform] = {
                'total_requests': 0,
                'successful_requests': 0,
                'avg_response_time': 0,
                'last_request': None
            }
        
        stats = self.scan_stats[platform]
        stats['total_requests'] += 1
        if success:
            stats['successful_requests'] += 1
        
        # Update average response time with exponential moving average
        alpha = 0.1  # Smoothing factor
        stats['avg_response_time'] = (
            alpha * response_time + 
            (1 - alpha) * stats['avg_response_time']
        )
        stats['last_request'] = datetime.now().isoformat()
    
    def should_rotate_platform(self, current_platform: str) -> bool:
        """Determine if we should rotate to a different platform"""
        config = self.platform_configs.get(current_platform, self.platform_configs['github'])
        error_count = config['error_count']
        
        # Rotate if we have too many consecutive errors
        return error_count > 5
    
    def adaptive_scan_loop(self):
        """Main adaptive scanning loop"""
        print(f"[*] Adaptive Throttler active: PID {os.getpid()}, nice={os.nice(0)}")
        
        # Wait for WiFi before starting
        self._wait_for_wifi_before_launch()
        
        # Command to run the mass scan with adaptive control
        # Keep jobs low on phones — 4 concurrent trufflehog clones was pegging
        # CPU with crypto_scanner and getting Termux LMK'd.
        try:
            mem_mb = 0.0
            with open("/proc/meminfo") as _mf:
                for _ln in _mf:
                    if _ln.startswith("MemAvailable:"):
                        mem_mb = int(_ln.split()[1]) / 1024.0
                        break
        except Exception:
            mem_mb = 0.0
        if mem_mb >= 6000:
            mass_jobs = "2"
        elif mem_mb >= 3000:
            mass_jobs = "2"
        else:
            mass_jobs = "1"
        mass_jobs = os.environ.get("MASS_SCAN_JOBS", mass_jobs)
        # Hard ceiling — never more than 3 on this device class
        try:
            if int(mass_jobs) > 3:
                mass_jobs = "3"
        except ValueError:
            mass_jobs = "2"
        cmd = [
            sys.executable,
            os.path.expanduser("~/.local/lib/trufflehog-tools/mass_scan.py"),
            "-f", os.path.expanduser("~/paste.txt"),
            "-j", str(mass_jobs),
            "-o", os.path.expanduser("~/.trufflehog_mass_results.jsonl"),
        ]
        
        print("[*] Launching mass scan with adaptive throttle:", " ".join(cmd))
        
        # Ensure child is niced too
        env = os.environ.copy()
        env.setdefault("MASS_SCAN_JOBS", str(mass_jobs))
        env.setdefault("BALANCE_WORKERS", env.get("BALANCE_WORKERS", "6"))
        env.setdefault("SCAN_FROM_END", env.get("SCAN_FROM_END", "0"))

        proc = subprocess.Popen(
            cmd,
            cwd=HOME,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
        try:
            os.setpriority(os.PRIO_PROCESS, proc.pid, 10)
        except Exception:
            pass

        
        def cleanup(signum=None, frame=None):
            print("[!] Caught signal, terminating child...")
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            try:
                os.remove(PID_FILE)
            except OSError:
                pass
            self.save_config()
            sys.exit(0)
        
        signal.signal(signal.SIGTERM, cleanup)
        signal.signal(signal.SIGINT, cleanup)
        
        # Main processing loop
        for line in proc.stdout:
            start_time = time.time()
            sys.stdout.write("[%s] %s" % (time.strftime("%H:%M:%S"), line))
            sys.stdout.flush()
            
            # Parse the line to extract platform info if available
            platform = self.extract_platform_from_line(line)
            if platform:
                response_time = time.time() - start_time
                success = "error" not in line.lower() and "failed" not in line.lower()
                
                # Update stats
                self.update_scan_stats(platform, success, response_time)
                
                # Calculate adaptive delay
                delay = self.get_adaptive_delay(platform, 200, not success)
                
                # Apply delay
                time.sleep(delay)
        
        ret = proc.wait()
        cleanup()
    
    def extract_platform_from_line(self, line: str) -> str:
        """Extract platform from log line if possible"""
        # Look for common platform indicators in the log line
        line_lower = line.lower()
        
        if 'github' in line_lower:
            return 'github'
        elif 'gitlab' in line_lower:
            return 'gitlab'
        elif 'huggingface' in line_lower:
            return 'huggingface'
        elif 'docker' in line_lower:
            return 'docker'
        elif 'circleci' in line_lower:
            return 'circleci'
        elif 'postman' in line_lower:
            return 'postman'
        elif 's3' in line_lower or 'aws' in line_lower:
            return 'aws_s3'
        elif 'gcs' in line_lower or 'google' in line_lower:
            return 'gcs'
        elif 'jenkins' in line_lower:
            return 'jenkins'
        elif 'elasticsearch' in line_lower:
            return 'elasticsearch'
        else:
            return 'unknown'
    
    # WiFi resilience helpers (copied from original)
    WIFI_WAIT_INTERVAL = 30  # seconds between connectivity checks

    def _is_wifi_connected(self, timeout=5):
        """Return True if the device has working internet connectivity."""
        try:
            import urllib.request
            urllib.request.urlopen("https://www.google.com", timeout=timeout)
            return True
        except Exception:
            return False

    def _wait_for_wifi(self):
        """Block until WiFi/internet connectivity is restored, then return."""
        start = time.time()
        while True:
            if self._is_wifi_connected():
                elapsed = time.time() - start
                print("[wifi] Connectivity restored after ~%.0fs — resuming." % elapsed)
                return
            elapsed = time.time() - start
            print(
                "[wifi] No connectivity for ~%.0fs — retrying in %ds..."
                % (elapsed, self.WIFI_WAIT_INTERVAL)
            )
            time.sleep(self.WIFI_WAIT_INTERVAL)

    def _wait_for_wifi_before_launch(self):
        """Block until WiFi is available before starting the mass scan."""
        if self._is_wifi_connected():
            print("[wifi] Connectivity OK — starting adaptive scan.")
            return
        print("[wifi] No connectivity at launch — waiting for WiFi...")
        self._wait_for_wifi()

def main():
    throttler = AdaptiveThrottler()
    throttler.adaptive_scan_loop()

if __name__ == '__main__':
    main()
