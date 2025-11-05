# scanner/cli.py
import argparse
import asyncio

# Import the async run() from your scripts
from scanner.scripts.run_scan import run

def parse_args():
    p = argparse.ArgumentParser(prog="avscan", description="Async Vulnerability Scanner (avscan)")
    p.add_argument("target", help="Target URL or host to scan (e.g. https://example.com)")
    p.add_argument("--throttle", type=float, default=0.2, help="Delay between checks (seconds)")
    return p.parse_args()

def main():
    args = parse_args()

    # call run(...) trying to pass throttle if the function accepts it,
    # otherwise gracefully fallback to calling without the throttle param.
    try:
        asyncio.run(run(args.target, throttle=args.throttle))
    except TypeError:
        # fallback if run() doesn't accept throttle
        asyncio.run(run(args.target))

if __name__ == "__main__":
    main()
