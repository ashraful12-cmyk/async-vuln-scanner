# scanner/portscanner.py
import asyncio
from typing import List, Tuple

DEFAULT_TIMEOUT = 3.0

async def probe_port(host: str, port: int, sem: asyncio.Semaphore, timeout: float = DEFAULT_TIMEOUT) -> Tuple[int, bool, str]:
    """
    Returns (port, is_open, banner)
    """
    try:
        async with sem:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            # Try to read banner non-blocking
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = banner.decode(errors="ignore").strip()
            except Exception:
                banner = ""
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, True, banner
    except Exception:
        return port, False, ""

async def scan_ports(host: str, ports: List[int], concurrency: int = 500) -> List[dict]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [probe_port(host, p, sem) for p in ports]
    results = await asyncio.gather(*tasks)
    return [{"port": p, "open": is_open, "banner": b} for (p, is_open, b) in results]

if __name__ == "__main__":
    import sys, json
    host = sys.argv[1]
    ports = list(map(int, sys.argv[2].split(","))) if len(sys.argv) > 2 else list(range(1,1025))
    r = asyncio.run(scan_ports(host, ports, concurrency=500))
    print(json.dumps({"host": host, "results": r}, indent=2))
