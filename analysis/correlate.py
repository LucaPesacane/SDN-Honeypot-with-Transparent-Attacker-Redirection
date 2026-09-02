#!/usr/bin/env python3
"""
correlate.py - Correlazione fra eventi del controller e traffico catturato
               sull'honeypot.

Il controller registra QUANDO ha rilevato l'attacco e QUANDO ha installato le
regole di redirezione; la cattura sull'honeypot documenta CHE COSA e' poi
effettivamente arrivato a destinazione. Unendo le due sorgenti si ottiene la
timeline completa della catena detection -> mitigazione -> osservazione, che
e' il risultato che giustifica la scelta di deviare il traffico anziche'
scartarlo: con un semplice drop non esisterebbe alcuna evidenza successiva
alla rilevazione.

Non richiede dipendenze esterne: il pcap viene letto invocando tcpdump.

Uso:
  python3 correlate.py
  python3 correlate.py --alerts /tmp/ncis_alerts.jsonl \\
                       --pcap /tmp/honeypot.pcap \\
                       --out /tmp/timeline.csv
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from collections import Counter

# tcpdump -tt -nn produce righe del tipo:
# 1788185479.146 IP 10.0.0.10.44321 > 10.0.0.200.5001: Flags [S], ...
LINE_RE = re.compile(
    r'^(?P<ts>\d+\.\d+)\s+IP\s+'
    r'(?P<src>\d+\.\d+\.\d+\.\d+)\.(?P<sport>\d+)\s+>\s+'
    r'(?P<dst>\d+\.\d+\.\d+\.\d+)\.(?P<dport>\d+):\s+'
    r'(?P<rest>.*)$'
)
FLAGS_RE = re.compile(r'Flags \[([^\]]*)\]')


def read_alerts(path):
    """Legge il log JSON Lines prodotto dal controller."""
    if not os.path.exists(path):
        print('[!] file alert non trovato: %s' % path, file=sys.stderr)
        return []
    events = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    return events


def read_pcap(path):
    """Estrae i pacchetti dal pcap invocando tcpdump."""
    if not os.path.exists(path):
        print('[!] pcap non trovato: %s' % path, file=sys.stderr)
        return []
    try:
        out = subprocess.run(
            ['tcpdump', '-r', path, '-tt', '-nn'],
            capture_output=True, text=True, check=False).stdout
    except FileNotFoundError:
        print('[!] tcpdump non disponibile', file=sys.stderr)
        return []

    pkts = []
    for line in out.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        d = m.groupdict()
        fm = FLAGS_RE.search(d['rest'])
        pkts.append({
            'ts': float(d['ts']),
            'src': d['src'],
            'dst': d['dst'],
            'sport': int(d['sport']),
            'dport': int(d['dport']),
            'flags': fm.group(1) if fm else '',
        })
    return pkts


def summarise_capture(pkts, hp_ip):
    """Statistiche del traffico osservato sull'honeypot."""
    inbound = [p for p in pkts if p['dst'] == hp_ip]
    outbound = [p for p in pkts if p['src'] == hp_ip]
    sources = Counter(p['src'] for p in inbound)
    ports = Counter(p['dport'] for p in inbound)
    syns = [p for p in inbound if 'S' in p['flags'] and '.' not in p['flags']]
    return {
        'packets_total': len(pkts),
        'packets_inbound': len(inbound),
        'packets_outbound': len(outbound),
        'distinct_sources': len(sources),
        'distinct_ports_contacted': len(ports),
        'syn_received': len(syns),
        'top_sources': sources.most_common(5),
        'top_ports': ports.most_common(10),
        'first_ts': min((p['ts'] for p in pkts), default=None),
        'last_ts': max((p['ts'] for p in pkts), default=None),
    }


def build_timeline(alerts, pkts, hp_ip):
    """
    Costruisce la timeline unificata. Per ogni alert si cerca il primo
    pacchetto arrivato all'honeypot dalla stessa sorgente in un istante
    successivo: e' la prova che la regola installata ha avuto effetto.
    """
    rows = []
    for a in alerts:
        ts = a.get('timestamp')
        src = a.get('src_ip')
        kind = a.get('event', 'alert')

        row = {
            'timestamp': '%.3f' % ts if ts else '',
            'datetime': a.get('datetime', ''),
            'event': kind,
            'src_ip': src,
            'attack_type': a.get('attack_type', ''),
            'action': a.get('action', ''),
            'evidence_dports': a.get('evidence', {}).get('distinct_dports', ''),
            'first_pkt_at_honeypot': '',
            'redirect_latency_s': '',
            'pkts_from_src_at_honeypot': '',
        }

        if kind == 'alert' and ts and src:
            later = [p for p in pkts
                     if p['src'] == src and p['dst'] == hp_ip and p['ts'] >= ts]
            row['pkts_from_src_at_honeypot'] = len(later)
            if later:
                first = min(p['ts'] for p in later)
                row['first_pkt_at_honeypot'] = '%.3f' % first
                row['redirect_latency_s'] = '%.3f' % (first - ts)

        if kind == 'recovery':
            row['evidence_dports'] = ''
            row['action'] = 'quarantine_end (%.1fs, %s pkt)' % (
                a.get('quarantine_duration_s', 0),
                a.get('redirected_packets', 0))

        rows.append(row)

    rows.sort(key=lambda r: r['timestamp'])
    return rows


def main():
    ap = argparse.ArgumentParser(description='Correlazione alert / cattura')
    ap.add_argument('--alerts', default='/tmp/ncis_alerts.jsonl')
    ap.add_argument('--pcap', default='/tmp/honeypot.pcap')
    ap.add_argument('--honeypot-ip', default='10.0.0.200')
    ap.add_argument('--out', default='/tmp/timeline.csv')
    args = ap.parse_args()

    alerts = read_alerts(args.alerts)
    pkts = read_pcap(args.pcap)

    print('=' * 68)
    print('EVENTI DEL CONTROLLER')
    print('=' * 68)
    n_alert = sum(1 for a in alerts if a.get('event') == 'alert')
    n_rec = sum(1 for a in alerts if a.get('event') == 'recovery')
    print('  alert emessi:            %d' % n_alert)
    print('  recovery registrati:     %d' % n_rec)

    print()
    print('=' * 68)
    print('TRAFFICO OSSERVATO SULL\'HONEYPOT')
    print('=' * 68)
    if pkts:
        s = summarise_capture(pkts, args.honeypot_ip)
        print('  pacchetti catturati:     %d' % s['packets_total'])
        print('  in ingresso / uscita:    %d / %d'
              % (s['packets_inbound'], s['packets_outbound']))
        print('  sorgenti distinte:       %d' % s['distinct_sources'])
        print('  porte contattate:        %d' % s['distinct_ports_contacted'])
        print('  SYN ricevuti:            %d' % s['syn_received'])
        if s['first_ts']:
            print('  durata cattura:          %.1f s'
                  % (s['last_ts'] - s['first_ts']))
        print('  sorgenti principali:')
        for ip, n in s['top_sources']:
            print('      %-15s %d pacchetti' % (ip, n))
        print('  porte piu\' contattate:')
        for p, n in s['top_ports']:
            print('      porta %-6d %d pacchetti' % (p, n))
        print()
        print('  NOTA: ogni pacchetto qui registrato e\' per costruzione')
        print('  traffico ostile: nessun host legittimo ha motivo di')
        print('  contattare l\'honeypot, che non e\' raggiungibile se non')
        print('  attraverso la redirezione decisa dal controller.')
    else:
        print('  nessun pacchetto (cattura assente o vuota)')

    rows = build_timeline(alerts, pkts, args.honeypot_ip)
    if rows:
        print()
        print('=' * 68)
        print('TIMELINE')
        print('=' * 68)
        print('  %-14s %-10s %-12s %-9s %s'
              % ('orario', 'evento', 'sorgente', 'lat.(s)', 'azione'))
        for r in rows:
            print('  %-14s %-10s %-12s %-9s %s'
                  % (r['datetime'][11:] or r['timestamp'][:10],
                     r['event'], r['src_ip'] or '-',
                     r['redirect_latency_s'] or '-', r['action']))

        with open(args.out, 'w', newline='') as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print()
        print('  timeline salvata in %s' % args.out)


if __name__ == '__main__':
    main()
