#!/usr/bin/env python3
"""
WP + Joomla Detector - Memory-Safe
- Streaming baca file (tidak load semua ke RAM)
- Batched futures (queue terbatas)
- Deteksi WordPress + Joomla
- Cocok untuk file >50 MB
"""

import os
import re
import sys
import time
import json
import requests
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from urllib.parse import urljoin

urllib3.disable_warnings()

# ============ CONFIG ============
WEBHOOK = "" # your discord webhook
OUT = "results"
THREADS = 20
TIMEOUT = 15
BATCH_SIZE = THREADS * 4        # Queue futures max 80
CHECKPOINT_EVERY = 5000         # Save checkpoint setiap 5000 URL
MAX_HTML_BYTES = 1_048_576      # 1 MB max HTML per site

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

# ============ REGEX ============
# WordPress
RE_WP_META = re.compile(
    r'<meta\s+(?:name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)["\']'
    r'|content=["\']WordPress\s+([\d.]+)["\']\s+name=["\']generator["\'])\s*/?>',
    re.I
)
RE_PLUGIN = re.compile(r'/wp-content/plugins/([a-zA-Z0-9_\-]+)/', re.I)
RE_THEME = re.compile(r'/wp-content/themes/([a-zA-Z0-9_\-]+)/', re.I)
SKIP = {'', 'plugins', 'themes', 'cache', 'uploads', 'upgrade', 'temp'}

# Joomla
RE_JOOMLA_META = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']*joomla[^"\']*)["\']',
    re.I
)
RE_JOOMLA_VERSION = re.compile(
    r'Joomla!?\s*[-–]?\s*([\d]+\.[\d]+(?:\.[\d]+)?)', re.I)
JOOMLA_PATHS = (
    '/administrator/',
    '/components/com_',
    '/modules/mod_',
    '/templates/system/',
    '/media/jui/',
    '/media/system/js/core.js',
    '/language/en-GB/',
    'index.php?option=com_',
)

# ============ STATE ============
locks = {}
locks_lock = Lock()
stats_lock = Lock()
seen_lock = Lock()

stat = {
    'total': 0,
    'wp': 0, 'wp_ver': 0, 'plug': 0, 'theme': 0,
    'joomla': 0, 'joomla_ver': 0,
    'err': 0,
}
seen_all = set()
seen_plug = set()
seen_theme = set()
seen_joomla = set()


# ============ WRITE ============
def get_lock(key):
    with locks_lock:
        if key not in locks:
            locks[key] = Lock()
        return locks[key]


def write(cat, slug, url):
    lock = get_lock(f"{cat}/{slug}")
    if cat == 'ver':
        path = f"{OUT}/ver{slug}.txt"
    elif cat == 'jver':
        path = f"{OUT}/joomla/ver{slug}.txt"
    elif cat == 'all':
        path = f"{OUT}/result-all.txt"
    elif cat == 'wp':
        path = f"{OUT}/result-wp.txt"
    elif cat == 'joomla':
        path = f"{OUT}/result-joomla.txt"
    else:
        os.makedirs(f"{OUT}/{cat}", exist_ok=True)
        path = f"{OUT}/{cat}/{slug}.txt"

    with lock:
        with open(path, 'a') as f:
            f.write(f"{url}\n")
            f.flush()


def write_all(url):
    with seen_lock:
        if url in seen_all:
            return
        seen_all.add(url)
    write('all', '', url)


# ============ DISCORD ============
def notify(content=None, embed=None, file=None):
    if not WEBHOOK:
        return
    try:
        if file and os.path.exists(file):
            with open(file, 'rb') as f:
                data = {'username': 'WP+Joomla Detector'}
                if content:
                    data['content'] = content[:1900]
                if embed:
                    data['embeds'] = json.dumps([embed])[:5900]
                requests.post(WEBHOOK, data=data, files={
                              'file': f}, timeout=30)
        else:
            payload = {'username': 'WP+Joomla Detector'}
            if content:
                payload['content'] = content[:1900]
            if embed:
                payload['embeds'] = [embed]
            requests.post(WEBHOOK, json=payload, timeout=15)
    except Exception:
        pass


# ============ JOOMLA DETECT ============
def detect_joomla(session, base_url, html):
    """
    Return (version_or_None, evidence_list)
    """
    evidence = []

    # 1. Meta generator
    m = RE_JOOMLA_META.search(html)
    if m:
        evidence.append('meta-generator')
        vm = RE_JOOMLA_VERSION.search(m.group(1))
        if vm:
            return vm.group(1), evidence

    # 2. Path khas di HTML
    hits = [p for p in JOOMLA_PATHS if p.lower() in html.lower()]
    if hits:
        evidence.extend(hits[:3])

    # 3. Cookie Joomla
    try:
        cookies_str = " ".join(session.cookies.get_dict().keys()).lower()
        if 'joomla' in cookies_str:
            evidence.append('cookie')
    except Exception:
        pass

    # 4. Manifest XML (memberi versi)
    try:
        manifest = urljoin(
            base_url + '/', 'administrator/manifests/files/joomla.xml')
        mr = session.get(manifest, timeout=TIMEOUT, verify=False)
        if mr.status_code == 200 and '<name>files_joomla</name>' in mr.text:
            ver = re.search(r'<version>([^<]+)</version>', mr.text)
            v = ver.group(1) if ver else None
            evidence.append('manifest-xml')
            if v:
                return v, evidence
    except Exception:
        pass

    # 5. Language XML
    try:
        lang = urljoin(base_url + '/', 'language/en-GB/en-GB.xml')
        lr = session.get(lang, timeout=TIMEOUT, verify=False)
        if lr.status_code == 200 and '<name>English (en-GB)</name>' in lr.text:
            evidence.append('lang-xml')
    except Exception:
        pass

    if evidence:
        return None, evidence
    return None, []


# ============ SCAN ============
def scan(url):
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"

    session = requests.Session()
    session.headers.update(HEADERS)

    try:
        r = session.get(
            url, verify=False, timeout=TIMEOUT,
            allow_redirects=True, stream=True
        )

        # Batasi baca HTML max MAX_HTML_BYTES
        buf = b''
        for chunk in r.iter_content(16384):
            buf += chunk
            if len(buf) > MAX_HTML_BYTES:
                break
        final_url = r.url
        r.close()

        html = buf.decode('utf-8', errors='ignore')
        buf = None

        # ---------- WordPress check ----------
        wp_ver = None
        m = RE_WP_META.search(html)
        if m:
            wp_ver = m.group(1) or m.group(2)

        plugs = {s.lower()
                 for s in RE_PLUGIN.findall(html) if s.lower() not in SKIP}
        themes = {s.lower()
                  for s in RE_THEME.findall(html) if s.lower() not in SKIP}
        is_wp = bool(wp_ver or plugs or themes)

        # ---------- Joomla check ----------
        joomla_ver, joomla_ev = (None, [])
        # Heuristik cepat: hanya cek lanjutan jika ada indikasi
        quick_hit = (
            'joomla' in html.lower() or
            any(p.lower() in html.lower() for p in JOOMLA_PATHS)
        )
        if quick_hit:
            joomla_ver, joomla_ev = detect_joomla(session, final_url, html)
        is_joomla = bool(joomla_ev)

        html = None  # free memory

        return {
            'status': 'ok',
            'url': final_url,
            'is_wp': is_wp,
            'wp_ver': wp_ver,
            'plugs': plugs,
            'themes': themes,
            'is_joomla': is_joomla,
            'joomla_ver': joomla_ver,
            'joomla_ev': joomla_ev,
        }

    except requests.exceptions.Timeout:
        return {'status': 'timeout', 'url': url}
    except Exception:
        return {'status': 'error', 'url': url}
    finally:
        try:
            session.close()
        except Exception:
            pass


# ============ WORKER ============
def worker(i, total, url):
    res = scan(url)
    short = res['url'][:55]
    status = res['status']

    if status != 'ok':
        print(f"\r[{i:>7}/{total}] ✗ {status:<7} {short}")
        with stats_lock:
            stat['err'] += 1
        return

    is_wp = res['is_wp']
    is_joomla = res['is_joomla']

    # ---------- NOTHING ----------
    if not is_wp and not is_joomla:
        print(f"\r[{i:>7}/{total}] · none    {short}")
        return

    # ---------- BUILD TAGS ----------
    tags = []
    if is_wp:
        tags.append('WP')
        if res['wp_ver']:
            tags.append(f"v{res['wp_ver']}")
        if res['plugs']:
            tags.append(f"{len(res['plugs'])}P")
        if res['themes']:
            tags.append(f"{len(res['themes'])}T")
    if is_joomla:
        tags.append('JML')
        if res['joomla_ver']:
            tags.append(f"v{res['joomla_ver']}")

    print(f"\r[{i:>7}/{total}] ✓ {' '.join(tags):<20} {short}")

    # ---------- WRITE WORDPRESS ----------
    if is_wp:
        write('wp', '', res['url'])
        if res['wp_ver']:
            write('ver', res['wp_ver'], res['url'])
            with stats_lock:
                stat['wp_ver'] += 1
        for p in res['plugs']:
            write('plugins', p, res['url'])
            with seen_lock:
                seen_plug.add(p)
            with stats_lock:
                stat['plug'] += 1
        for t in res['themes']:
            write('themes', t, res['url'])
            with seen_lock:
                seen_theme.add(t)
            with stats_lock:
                stat['theme'] += 1
        with stats_lock:
            stat['wp'] += 1

    # ---------- WRITE JOOMLA ----------
    if is_joomla:
        write('joomla', '', res['url'])
        if res['joomla_ver']:
            write('jver', res['joomla_ver'], res['url'])
            with stats_lock:
                stat['joomla_ver'] += 1
        with seen_lock:
            seen_joomla.add(res['url'])
        with stats_lock:
            stat['joomla'] += 1

    write_all(res['url'])


# ============ STREAMING READ ============
def count_lines(path):
    n = 0
    with open(path, 'rb') as f:
        for _ in f:
            n += 1
    return n


def read_urls(path):
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                yield line


# ============ MAIN ============
def main():
    print("\n=== WP + JOOMLA DETECTOR (Memory-Safe) ===\n")

    path = input("File list: ").strip() or "list.txt"
    if not os.path.exists(path):
        print(f"✗ {path} not found")
        return

    size_mb = os.path.getsize(path) / 1_048_576
    print(f"[*] File size: {size_mb:.1f} MB")

    if size_mb > 20:
        print(f"[!] File besar (>20MB) - pakai streaming mode")

    threads = input(f"Threads (default {THREADS}): ").strip()
    threads = int(threads) if threads.isdigit() else THREADS

    # Count lines (streaming)
    print("[*] Counting lines...")
    total = count_lines(path)
    stat['total'] = total
    print(f"[*] Total lines: {total:,}")

    # Setup output dirs
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(f"{OUT}/plugins", exist_ok=True)
    os.makedirs(f"{OUT}/themes", exist_ok=True)
    os.makedirs(f"{OUT}/joomla", exist_ok=True)

    # Clean output
    for root, _, files in os.walk(OUT):
        for f in files:
            if f.endswith('.txt'):
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass

    # Init files
    open(f"{OUT}/result-all.txt", 'w').close()
    open(f"{OUT}/result-wp.txt", 'w').close()
    open(f"{OUT}/result-joomla.txt", 'w').close()

    print(f"\n[*] {total:,} URLs, {threads} threads")
    print(f"[*] Batch size: {threads * 4}")
    print(f"[*] Output: {OUT}/\n")

    notify(
        content=f"🚀 Scan started\n• {total:,} URLs • {threads} threads • WP+Joomla")

    start = time.time()
    batch_size = threads * 4

    with ThreadPoolExecutor(max_workers=threads) as ex:
        batch = []
        for i, url in enumerate(read_urls(path), 1):
            batch.append(ex.submit(worker, i, total, url))

            if len(batch) >= batch_size:
                for _ in as_completed(batch):
                    pass
                batch.clear()

                if i % CHECKPOINT_EVERY == 0:
                    elapsed = time.time() - start
                    rate = i / elapsed if elapsed else 0
                    print(f"\n[CP] {i:,}/{total:,} | "
                          f"WP:{stat['wp']} | JML:{stat['joomla']} | "
                          f"{rate:.1f}/s | "
                          f"ETA: {(total - i) / rate / 60:.1f}min\n")

        if batch:
            for _ in as_completed(batch):
                pass

    elapsed = time.time() - start
    print("\n\n")

    # Summary
    print("=" * 52)
    print(f"  Total URLs      : {stat['total']:,}")
    print(f"  WordPress       : {stat['wp']:,}")
    print(f"  WP w/ version   : {stat['wp_ver']:,}")
    print(f"  Plugin hits     : {stat['plug']:,}")
    print(f"  Theme hits      : {stat['theme']:,}")
    print(f"  ---")
    print(f"  Joomla          : {stat['joomla']:,}")
    print(f"  Joomla w/ ver   : {stat['joomla_ver']:,}")
    print(f"  ---")
    print(f"  Errors          : {stat['err']:,}")
    print(f"  Unique plugins  : {len(seen_plug):,}")
    print(f"  Unique themes   : {len(seen_theme):,}")
    print(f"  Unique URLs     : {len(seen_all):,}")
    print(f"  Time            : {elapsed:.1f}s ({elapsed/60:.1f}min)")
    print("=" * 52 + "\n")

    notify(
        embed={
            "title": "✅ Scan Complete",
            "color": 0x3498db,
            "fields": [
                {"name": "Total",
                    "value": f"`{stat['total']:,}`", "inline": True},
                {"name": "WordPress",
                    "value": f"`{stat['wp']:,}`", "inline": True},
                {"name": "Joomla",
                    "value": f"`{stat['joomla']:,}`", "inline": True},
                {"name": "Plugins",
                    "value": f"`{len(seen_plug):,}`", "inline": True},
                {"name": "Themes",
                    "value": f"`{len(seen_theme):,}`", "inline": True},
                {"name": "Errors",
                    "value": f"`{stat['err']:,}`", "inline": True},
                {"name": "Time", "value": f"`{elapsed/60:.1f}min`", "inline": True},
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }
    )

    # Kirim file hasil
    for fname, label in [
        (f"{OUT}/result-all.txt", "all"),
        (f"{OUT}/result-joomla.txt", "joomla"),
    ]:
        if os.path.exists(fname) and 0 < os.path.getsize(fname) < 8_000_000:
            notify(content=f"📁 **{label}** results", file=fname)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped")
