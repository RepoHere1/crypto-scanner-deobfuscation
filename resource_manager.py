#!/usr/bin/env python3
"""
Resource Manager & Failover System for Crypto Scanner

Manages system resources, implements failover mechanisms, and provides
checkpoint/recovery capabilities for the scanning pipeline.
"""

import os
try:
    import psutil
except ImportError:
    psutil = None
import signal
import subprocess
import sys
import time
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import multiprocessing as mp

class ResourceManager:
    def __init__(self):
        self.home = Path.home()
        self.resource_stats_file = self.home / ".resource_stats.json"
        self.checkpoint_file = self.home / ".checkpoint.json"
        self.process_registry_file = self.home / ".process_registry.json"
        
        self.load_checkpoint()
        self.load_process_registry()
        self.setup_signal_handlers()
        
        # Resource thresholds
        self.cpu_threshold = 80  # percent
        self.memory_threshold = 85  # percent
        self.disk_threshold = 90  # percent
        
        # Process registry to track running services
        self.process_registry = {}
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        signal.signal(signal.SIGTERM, self.graceful_shutdown)
        signal.signal(signal.SIGINT, self.graceful_shutdown)
    
    def load_checkpoint(self):
        """Load checkpoint data from file."""
        try:
            with open(self.checkpoint_file, 'r') as f:
                self.checkpoint = json.load(f)
        except FileNotFoundError:
            self.checkpoint = {
                'last_scan_position': 0,
                'completed_targets': [],
                'failed_targets': [],
                'last_update': datetime.now().isoformat()
            }
    
    def save_checkpoint(self):
        """Save checkpoint data to file."""
        self.checkpoint['last_update'] = datetime.now().isoformat()
        with open(self.checkpoint_file, 'w') as f:
            json.dump(self.checkpoint, f, indent=2)
    
    def load_process_registry(self):
        """Load process registry from file."""
        try:
            with open(self.process_registry_file, 'r') as f:
                self.process_registry = json.load(f)
        except FileNotFoundError:
            self.process_registry = {}
    
    def save_process_registry(self):
        """Save process registry to file."""
        with open(self.process_registry_file, 'w') as f:
            json.dump(self.process_registry, f, indent=2)
    
    def register_process(self, name: str, pid: int, status: str = "running"):
        """Register a process in the registry."""
        self.process_registry[name] = {
            'pid': pid,
            'status': status,
            'registered_at': datetime.now().isoformat()
        }
        self.save_process_registry()
    
    def unregister_process(self, name: str):
        """Unregister a process from the registry."""
        if name in self.process_registry:
            del self.process_registry[name]
            self.save_process_registry()
    
    def get_system_resources(self) -> Dict[str, Any]:
        """Get current system resource usage."""
        # Try to get resources using psutil if available, otherwise use basic methods
        if psutil is not None:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
            available_memory_gb = psutil.virtual_memory().available / (1024**3)
            total_processes = len(psutil.pids())
        else:
            # Basic fallback without psutil
            cpu_percent = 50  # Default assumption
            memory_percent = 50  # Default assumption
            disk_percent = 50   # Default assumption
            available_memory_gb = 1.0  # Default assumption
            total_processes = 100  # Default assumption
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'disk_percent': disk_percent,
            'available_memory_gb': available_memory_gb,
            'total_processes': total_processes,
            'timestamp': datetime.now().isoformat()
        }
    
    def is_resource_available(self) -> bool:
        """Check if system resources are available for scanning."""
        resources = self.get_system_resources()
        
        # Check if any threshold is exceeded
        if resources['cpu_percent'] > self.cpu_threshold:
            print(f"[Resource Manager] High CPU usage: {resources['cpu_percent']:.1f}%")
            return False
        
        if resources['memory_percent'] > self.memory_threshold:
            print(f"[Resource Manager] High memory usage: {resources['memory_percent']:.1f}%")
            return False
        
        if resources['disk_percent'] > self.disk_threshold:
            print(f"[Resource Manager] High disk usage: {resources['disk_percent']:.1f}%")
            return False
        
        return True
    
    def scale_down_services(self):
        """Scale down services to free up resources."""
        print("[Resource Manager] Scaling down services due to resource pressure...")
        
        # Get all scanner-related processes (basic implementation without psutil)
        import subprocess
        try:
            # Use pgrep to find processes
            result = subprocess.run(['pgrep', '-f', 'crypto_scanner|trufflehog|mass_scan'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                scanner_pids = [int(pid) for pid in result.stdout.strip().split('\n') if pid]
            else:
                scanner_pids = []
        except (subprocess.SubprocessError, FileNotFoundError):
            scanner_pids = []  # Fallback if pgrep is not available
        
        # Reduce priority of scanner processes
        for pid in scanner_pids:
            try:
                # On Unix-like systems, os.nice affects current process only
                # To change other processes, we'd need to use system commands
                subprocess.run(['renice', '10', str(pid)], capture_output=True)
                print(f"[Resource Manager] Reduced priority of process {pid}")
            except (subprocess.SubprocessError, PermissionError):
                continue
    
    def monitor_resources(self):
        """Monitor system resources continuously."""
        def resource_monitor():
            while True:
                try:
                    if not self.is_resource_available():
                        self.scale_down_services()
                    
                    time.sleep(30)  # Check every 30 seconds
                except Exception as e:
                    print(f"[Resource Manager] Error in resource monitoring: {e}")
                    time.sleep(30)
        
        # Start resource monitoring in a separate thread
        monitor_thread = threading.Thread(target=resource_monitor, daemon=True)
        monitor_thread.start()
        return monitor_thread
    
    def checkpoint_and_continue(self, current_position: int, completed_items: List[str] = None):
        """Save current progress and continue."""
        if completed_items is None:
            completed_items = []
        
        self.checkpoint['last_scan_position'] = current_position
        self.checkpoint['completed_targets'].extend(completed_items)
        self.save_checkpoint()
    
    def recover_from_checkpoint(self):
        """Recover scanning from last checkpoint."""
        print(f"[Resource Manager] Recovering from checkpoint...")
        print(f"  Last position: {self.checkpoint['last_scan_position']}")
        print(f"  Completed targets: {len(self.checkpoint['completed_targets'])}")
        print(f"  Failed targets: {len(self.checkpoint['failed_targets'])}")
        
        return {
            'position': self.checkpoint['last_scan_position'],
            'completed': self.checkpoint['completed_targets'],
            'failed': self.checkpoint['failed_targets']
        }
    
    def spawn_worker_process(self, target_func, args=(), name: str = None) -> Optional[int]:
        """Safely spawn a worker process with resource monitoring."""
        if not self.is_resource_available():
            print(f"[Resource Manager] Insufficient resources to spawn {name}")
            return None
        
        try:
            # Use subprocess to spawn the process
            if name is None:
                name = f"worker_{int(time.time())}"
            
            # Start the process
            proc = subprocess.Popen([
                sys.executable, '-c', 
                f'import sys; from {target_func.__module__} import {target_func.__name__}; '
                f'{target_func.__name__}(*{repr(args)})'
            ])
            
            # Register the process
            self.register_process(name, proc.pid)
            return proc.pid
            
        except Exception as e:
            print(f"[Resource Manager] Failed to spawn process {name}: {e}")
            return None
    
    def monitor_process_health(self, name: str, pid: int) -> bool:
        """Monitor a process health and restart if necessary."""
        try:
            # On systems without psutil, use os.kill to check if process exists
            os.kill(pid, 0)  # Check if process exists without killing
            return True
        except OSError:
            # Process doesn't exist
            print(f"[Resource Manager] Process {name} (PID {pid}) no longer exists")
            self.unregister_process(name)
            return False
    
    def graceful_shutdown(self, signum=None, frame=None):
        """Handle graceful shutdown of all processes."""
        print("[Resource Manager] Initiating graceful shutdown...")
        
        # Save current checkpoint
        self.save_checkpoint()
        
        # Terminate registered processes
        for name, proc_info in self.process_registry.items():
            try:
                pid = proc_info['pid']
                print(f"[Resource Manager] Terminating process {name} (PID {pid})")
                os.kill(pid, signal.SIGTERM)  # Send termination signal
                
                # Wait briefly to see if it terminates
                time.sleep(1)
                
                # Check if process still exists and force kill if needed
                try:
                    os.kill(pid, 0)  # Check if process still exists
                    # Process still exists, force kill
                    os.kill(pid, signal.SIGKILL)  # Force kill if it didn't terminate
                except OSError:
                    pass  # Process already terminated
            except (OSError, ProcessLookupError):
                continue  # Process already terminated
        
        # Clear process registry
        self.process_registry.clear()
        self.save_process_registry()
        
        print("[Resource Manager] Shutdown complete")
        sys.exit(0)
    
    def auto_scale_workers(self, current_workers: int) -> int:
        """Determine optimal number of workers based on current resources."""
        resources = self.get_system_resources()
        
        # Base number of workers on available memory (each worker needs ~100MB)
        available_memory_mb = resources['available_memory_gb'] * 1024
        max_by_memory = max(1, int(available_memory_mb / 100))
        
        # Factor in CPU availability (use fewer workers if CPU is busy)
        cpu_factor = (100 - resources['cpu_percent']) / 100
        max_by_cpu = max(1, int(current_workers * cpu_factor * 1.5))
        
        # Take minimum of both constraints
        optimal_workers = min(max_by_memory, max_by_cpu, 8)  # Cap at 8 workers
        
        return max(1, optimal_workers)  # At least 1 worker

def main():
    rm = ResourceManager()
    
    print("Resource Manager initialized")
    print(f"System resources: {rm.get_system_resources()}")
    
    # Start resource monitoring
    monitor_thread = rm.monitor_resources()
    
    # Example: simulate checking resource availability
    if rm.is_resource_available():
        print("System has sufficient resources for scanning")
    else:
        print("System resource constraints detected")
    
    # Example: simulate checkpoint operations
    rm.checkpoint_and_continue(150, ['target1', 'target2', 'target3'])
    recovery_data = rm.recover_from_checkpoint()
    
    print(f"Simulated recovery: position={recovery_data['position']}")
    
    # Keep running to demonstrate monitoring
    try:
        time.sleep(10)  # Simulate work
    except KeyboardInterrupt:
        rm.graceful_shutdown()

if __name__ == '__main__':
    main()
