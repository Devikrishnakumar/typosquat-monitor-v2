"""
ct_stream_client.py
Async CT ingestion: WebSocket reader -> fast filter -> asyncio.Queue -> N workers.
The reader never blocks on DNS/Playwright/RDAP.
"""

import argparse
import asyncio
import json
from collections import OrderedDict

import websockets

from .permutation_filter import get_brand_settings, build_permutation_set, is_suspicious
from .pipeline import process_candidate
from src.storage.db import init_db
from src.enrichment.screenshot import ensure_reference_screenshot

CERTSTREAM_URL = "ws://localhost:8081/full-stream"
QUEUE_MAX = 5000        # backlog limit; extra candidates are dropped and counted
SEEN_MAX = 50000        # recent domains remembered for de-duplication

stats = {"messages": 0, "matched": 0, "duplicates": 0,
         "dropped": 0, "processed": 0, "errors": 0}


class RecentSet:
    """Bounded set so the same domain isn't processed repeatedly."""

    def __init__(self, maxlen):
        self.maxlen = maxlen
        self.data = OrderedDict()

    def add_if_new(self, item):
        if item in self.data:
            return False
        self.data[item] = None
        if len(self.data) > self.maxlen:
            self.data.popitem(last=False)
        return True


async def producer(queue, permutation_set, official_domain, seen):
    backoff = 1
    while True:
        try:
            async with websockets.connect(CERTSTREAM_URL, max_size=None, ping_interval=20) as ws:
                print("Connected to certstream-server-go. Watching for typosquat matches...\n")
                backoff = 1
                async for message in ws:
                    stats["messages"] += 1
                    try:
                        data = json.loads(message)
                        if data.get("message_type") != "certificate_update":
                            continue
                        domains = data["data"]["leaf_cert"].get("all_domains", [])
                    except (ValueError, KeyError, TypeError):
                        continue

                    for domain in domains:
                        if not is_suspicious(domain, permutation_set, official_domain=official_domain):
                            continue
                        stats["matched"] += 1
                        if not seen.add_if_new(domain):
                            stats["duplicates"] += 1
                            continue
                        try:
                            queue.put_nowait(domain)
                        except asyncio.QueueFull:
                            stats["dropped"] += 1
        except (websockets.exceptions.WebSocketException, OSError) as e:
            print(f"Connection lost ({e}). Reconnecting in {backoff}s...")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)


async def worker(name, queue, official_domain):
    while True:
        domain = await queue.get()
        try:
            # Existing code is blocking (requests, Playwright sync API, sqlite3),
            # so run it in a thread and keep the event loop free.
            await asyncio.to_thread(process_candidate, domain, official_domain)
            stats["processed"] += 1
        except Exception as e:
            stats["errors"] += 1
            print(f"[{name}] Error processing {domain}: {e}", flush=True)
        finally:
            queue.task_done()


async def stats_reporter(queue):
    while True:
        await asyncio.sleep(30)
        print(f"[STATS] {stats} | queue_size={queue.qsize()}", flush=True)


async def main(official_domain, permutation_set, num_workers):
    queue = asyncio.Queue(maxsize=QUEUE_MAX)
    seen = RecentSet(SEEN_MAX)

    tasks = [asyncio.create_task(producer(queue, permutation_set, official_domain, seen))]
    tasks += [asyncio.create_task(worker(f"worker-{i + 1}", queue, official_domain))
              for i in range(num_workers)]
    tasks.append(asyncio.create_task(stats_reporter(queue)))

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--brand", help="Override brand domain, e.g. flipkart.com")
    parser.add_argument("--workers", type=int, default=4, help="Number of enrichment workers")
    args = parser.parse_args()

    init_db()
    official_domain = get_brand_settings(cli_brand=args.brand)
    permutation_set = build_permutation_set(official_domain)
    ensure_reference_screenshot(official_domain)

    print(f"\nMonitoring for typosquats of: {official_domain}")
    print(f"Loaded {len(permutation_set)} permutations to watch for.")
    print(f"Starting {args.workers} workers.\n")

    try:
        asyncio.run(main(official_domain, permutation_set, args.workers))
    except KeyboardInterrupt:
        print("\nStopped.")
