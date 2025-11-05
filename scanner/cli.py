# scanner/cli.py
import argparse
import asyncio
from scanner.scripts.run_scan import run  # reuse your run() function

def parse_args():
    p = argparse.ArgumentParser(prog="avscan", description="Async vuln scanner")
    p.add_argument("target", help="Target URL or host")
    return p.parse_args()

def main():
    args = parse_args()
    asyncio.run(run(args.target))
