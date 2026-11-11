#!/usr/bin/env python3
import datetime, json, os, re, subprocess, sys

D = os.environ.get('SLM_DIR', '/etc/sing-box')
FAKE = os.environ.get('SLM_FAKE_NFT')
BASE = 21000


def load(name, default):
    try:
        with open(os.path.join(D, name), encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def nft(*args):
    if FAKE:
        return ''
    try:
        return subprocess.run(('nft',) + args, capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return ''


def counters():
    if FAKE:
        try:
            with open(FAKE, encoding='utf-8') as f:
                text = f.read()
        except Exception:
            text = ''
    else:
        text = nft('list', 'counters', 'table', 'inet', 'slm')
    return {m.group(1): int(m.group(2)) for m in re.finditer(r'counter (\w+) \{\s*packets \d+ bytes (\d+)', text)}


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ''
    meta = load('slm-meta.json', {})
    usage = load('slm-usage.json', {})
    users = usage.get('users') if isinstance(usage.get('users'), dict) else {}
    raw = {} if mode == 'reloaded' else counters()
    known = [u for u in meta.get('users', []) if isinstance(u, dict) and isinstance(u.get('id'), int)]
    fresh = {}
    for u in known:
        key = str(u['id'])
        e = users.get(key) if isinstance(users.get(key), dict) else {}
        e = {k: int(e.get(k, 0)) for k in ('up', 'down', 'last_up', 'last_down')}
        if mode == 'reset' and len(sys.argv) > 2 and sys.argv[2] == key:
            e['up'] = e['down'] = 0
        for d in ('up', 'down'):
            if mode == 'reloaded':
                e['last_' + d] = 0
                continue
            r = raw.get(d + '_' + key)
            if r is None:
                continue
            last = e['last_' + d]
            e[d] += r - last if r >= last else r
            e['last_' + d] = r
        fresh[key] = e
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    blocked = []
    for u in known:
        if u.get('off'):
            continue
        e = fresh[str(u['id'])]
        limit = int(u.get('limit') or 0)
        exp = u.get('exp') or ''
        if (limit > 0 and e['up'] + e['down'] >= limit) or (exp and today > exp):
            blocked.append(u['id'])
    nft('flush', 'set', 'inet', 'slm', 'blocked')
    if blocked:
        nft('add', 'element', 'inet', 'slm', 'blocked', '{ ' + ', '.join(str(BASE + i) for i in blocked) + ' }')
    out = {'users': fresh, 'blocked': blocked, 'updated': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}
    tmp = os.path.join(D, 'slm-usage.json.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(out, f)
    os.replace(tmp, os.path.join(D, 'slm-usage.json'))


main()

