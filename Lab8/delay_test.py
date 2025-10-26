#!/usr/bin/env python3
import subprocess
import re
import time
import app_core

# ssh connection details
mininet_host = "mininet@10.224.79.89"
h1_cmd = "sudo mnexec -a 1 bash -c 'wget -O /dev/null -T 10 http://1.1.1.1:8080 2>&1'"

def run_remote_command(cmd):
    """Run a command remotely on the Mininet VM via SSH and return output."""
    full_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", mininet_host, cmd]
    result = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
    return result.stdout + result.stderr

def measure_wget_delay():

    print("Running wget test from H1...")
    try:
        start = time.time()
        output = run_remote_command(h1_cmd)
        elapsed = time.time() - start

        # Try to parse the transfer speed
        match = re.search(r'\(([\d\.]+)\s*(KB|MB|GB)/s\)', output)
        if match:
            speed = float(match.group(1))
            unit = match.group(2)
            # approximate conversion to bytes/s
            if unit == "KB":
                speed *= 1e3
            elif unit == "MB":
                speed *= 1e6
            elif unit == "GB":
                speed *= 1e9

            size_match = re.search(r'saved \[(\d+)/', output)
            if size_match:
                size = float(size_match.group(1))
                delay = size / speed
                return round(delay, 3)

        return round(elapsed, 3)  # fallback timing if parsing fails
    except subprocess.TimeoutExpired:
        print("wget timed out.")
        return None
    except Exception as e:
        print(f"wget failed: {e}")
        return None

def choose_best_delay():

    print("\nEvaluating end-to-end delay for all path options...\n")
    delays = {}

    # shortest path
    print("Applying shortest path...")
    app_core.shortest_path()
    time.sleep(3)
    d_short = measure_wget_delay()
    if d_short is not None:
        delays["shortest"] = d_short
        print(f"Shortest path delay: {d_short:.3f}s")
    else:
        print("Could not measure shortest path delay.")

    # longest path
    print("Applying longest path...")
    app_core.longest_path()
    time.sleep(3)
    d_long = measure_wget_delay()
    if d_long is not None:
        delays["longest"] = d_long
        print(f"Longest path delay: {d_long:.3f}s")
    else:
        print("Could not measure longest path delay.")

    # default path
    print("Applying default path")
    app_core.default_path()
    time.sleep(3)
    d_def = measure_wget_delay()
    if d_def is not None:
        delays["default"] = d_def
        print(f"Default path delay: {d_def:.3f}s")
    else:
        print("Could not measure default path delay.")

    # select best path
    if not delays:
        print("No valid delay measurements — keeping current path.")
        return

    best = min(delays, key=delays.get)
    print(f"\nBest path: {best.upper()} ({delays[best]:.3f}s)\n")

    # apply best
    if best == "shortest":
        app_core.shortest_path()
    elif best == "longest":
        app_core.longest_path()
    else:
        app_core.default_path()

    print(f"Optimal path ({best}) reactivated based on measured delay.\n")

def main():
    choose_best_delay()

if __name__ == "__main__":
    main()
