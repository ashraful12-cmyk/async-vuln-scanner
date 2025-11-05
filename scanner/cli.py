
# scanner/cli.py
import argparse
import asyncio
from scanner.scripts.run_scan import run

def main():
    parser = argparse.ArgumentParser(prog="avscan", description="Async Vulnerability Scanner (avscan)")
    parser.add_argument("target", help="Target URL or host to scan (e.g. https://example.com)")
    parser.add_argument("--throttle", type=float, default=0.2, help="Delay between checks (seconds)")
    args = parser.parse_args()

    # run the async scan runner
    asyncio.run(run(args.target, throttle=args.throttle))

if __name__ == "__main__":
    main()