import ctypes
import time
import socket
import struct
import sys
import os
from typing import Tuple, Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# =====================================================================
# C-Types Integration (DLL Loading & Setup)
# =====================================================================

class LogEntry(ctypes.Structure):
    """C struct mapping for Python."""
    _fields_ = [
        ("ip", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint32)
    ]

def load_c_core(dll_name: str = 'core.dll') -> ctypes.CDLL:
    dll_path = os.path.abspath(dll_name)
    try:
        core = ctypes.CDLL(dll_path)
        
        # Configuring signatures to ensure type safety in the C-Python bridge
        core.process_logs_fast.restype = ctypes.POINTER(LogEntry)
        core.process_logs_fast.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
        
        core.free_log_memory.argtypes = [ctypes.POINTER(LogEntry)]
        core.free_log_memory.restype = None
        
        return core
    except OSError as e:
        console.print(f"[bold red][!] Critical Error loading native library ({dll_name}):[/]\n{e}")
        sys.exit(1)

# =====================================================================
# Threat Detection Engine
# =====================================================================

def int_to_ipv4(ip_int: int) -> str:
    """Converts a 32-bit integer back to an IPv4 string format."""
    return socket.inet_ntoa(struct.pack('!I', ip_int))

def classify_traffic_pattern(request_count: int, duration_sec: int, timestamps: List[int]) -> Tuple[Optional[str], Optional[str]]:
    """
    Analyzes the temporal distribution of requests to identify anomalous patterns.
    """
    rate = request_count / (duration_sec if duration_sec > 0 else 1)
    
    if request_count <= 10:
        return None, None

    # Basic statistical calculations for behavioral analysis
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    mean_interval = sum(intervals) / len(intervals)
    deviations = [abs(i - mean_interval) for i in intervals]
    mean_deviation = sum(deviations) / len(deviations)
    
    max_interval = max(intervals)
    min_interval = min(intervals)

    # Heuristic Detection Rules
    if request_count > 150 and duration_sec <= 5:
        return "[bold red]L7 API Flood[/]", "Massive instant request volume"

    if request_count > 100 and max_interval >= 15 and min_interval <= 1:
        return "[bold dark_red]Pulsing Attack[/]", "Rate Limit evasion via intermittent bursts"

    if 120 <= request_count <= 300 and 3 < rate <= 10 and mean_deviation > 0.2:
        return "[bold orange3]Automated Fuzzing[/]", "Directory scanning and enumeration"

    if duration_sec > 100 and rate <= 0.5 and request_count >= 30:
        return "[bold blue]Low-and-Slow (Slowloris)[/]", "Slow exhaustion of server sockets/connections"

    if mean_deviation < 0.2 and mean_interval >= 4.0 and duration_sec >= 60:
        return "[bold bright_cyan]C2 Beaconing[/]", f"Robotic periodic communication ({mean_interval:.1f}s)"

    if request_count >= 100 and 1 <= rate <= 3:
        return "[bold magenta]Data Scraping[/]", "Methodical and continuous data extraction"

    if 40 <= request_count < 100 and rate >= 1.0:
        return "[bold yellow]Brute Force[/]", "Repetitive authentication attempts"

    return None, None

# =====================================================================
# Main Pipeline
# =====================================================================

def analyze_logs(file_path: str, core_lib: ctypes.CDLL):
    console.print(Panel.fit("[bold cyan]🛡️ Log Analyzer & Threat Intelligence[/]\n[italic]C Core (OpenMP) integrated via CTypes[/]", border_style="cyan"))
    
    total_lines_ref = ctypes.c_int(0)
    file_path_bytes = file_path.encode('utf-8')
    t_start = time.time()
    
    # Step 1: Delegate I/O and Sorting to the C runtime
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="[cyan]Delegating I/O and Sorting (Native Core)...", total=None)
        t_c_start = time.time()
        
        # Invoke the C function
        logs_ptr = core_lib.process_logs_fast(file_path_bytes, ctypes.byref(total_lines_ref))
        
        t_c_end = time.time()
    
    total_records = total_lines_ref.value
    if total_records <= 0 or not logs_ptr:
        console.print("[bold red][!] Failed to process the file. Check the path or permissions.[/]")
        return

    console.print(f"[bold green]✓ Native Core Finished:[/] [bold]{total_records:,}[/] events processed in [bold yellow]{t_c_end - t_c_start:.4f}s[/].\n")

    # Ensure memory allocated in C is freed, even if Python encounters an exception
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="[magenta]Applying Detection Heuristics (Python)...", total=None)
            
            report_table = Table(title="Detected Anomalies Report", border_style="red")
            report_table.add_column("Source IP", style="bold cyan", justify="center")
            report_table.add_column("Tactical Classification", justify="left")
            report_table.add_column("Behavioral Signature", style="dim", justify="left")
            report_table.add_column("Volume", style="bold red", justify="right")
            report_table.add_column("Duration", style="yellow", justify="right")

            idx = 0
            threats_found = 0

            # Step 2: Python iterates over the perfectly sorted array returned by C
            while idx < total_records:
                current_ip = logs_ptr[idx].ip
                end_idx = idx
                
                while end_idx < total_records and logs_ptr[end_idx].ip == current_ip:
                    end_idx += 1
                
                requests_for_ip = end_idx - idx
                if requests_for_ip >= 15:
                    ts_start = logs_ptr[idx].timestamp
                    ts_end = logs_ptr[end_idx - 1].timestamp
                    duration = ts_end - ts_start
                    
                    # Extract timestamps only for suspicious IPs to save CPU cycles
                    timestamps = [logs_ptr[i].timestamp for i in range(idx, end_idx)]
                    
                    threat_type, behavior = classify_traffic_pattern(requests_for_ip, duration, timestamps)
                    if threat_type:
                        report_table.add_row(int_to_ipv4(current_ip), threat_type, behavior, f"{requests_for_ip} reqs", f"{duration}s")
                        threats_found += 1
                
                idx = end_idx

        # Display Results
        t_end = time.time()
        if threats_found > 0:
            console.print(report_table)
        else:
            console.print("[bold green]✓ Clean traffic. No critical anomalies detected.[/]")

        console.print(f"\n[dim]Total pipeline execution time (C + Python): {t_end - t_start:.4f}s.[/]")

    finally:
        # Step 3: Clean up DLL memory
        core_lib.free_log_memory(logs_ptr)

if __name__ == "__main__":
    core_dll = load_c_core("core.dll") # Adjust DLL name if needed
    analyze_logs("teste.log", core_dll)