#!/usr/bin/env python3
"""
benign_traffic.py - Generatore di traffico benigno per il project work NCIs

Sostituisce D-ITG (non compilabile su GCC recenti) mantenendone le
caratteristiche essenziali ai fini del progetto:
  - interarrivo esponenziale (processo di Poisson), non periodico
  - mix di servizi su porte realistiche
  - flussi TCP di durata variabile + flusso UDP CBR tipo VoIP
  - log CSV con timestamp, porta, byte, RTT

Il punto chiave per il detector: un host benigno contatta POCHE porte
distinte e mantiene le connessioni aperte per piu' pacchetti. Un port
scan fa l'opposto. E' su questa differenza che si basa il rilevamento.

Uso:
  # sul server (h_srv)
  python3 benign_traffic.py server

  # sui client (h_ben1, h_ben2, h_ben3)
  python3 benign_traffic.py client --target 10.0.0.100 --duration 300 \
      --rate 2 --log /tmp/ben1.csv

  # flusso VoIP UDP costante
  python3 benign_traffic.py voip --target 10.0.0.100 --duration 300
"""

import argparse
import csv
import random
import socket
import sys
import threading
import time

# Porte dei servizi "esposti" dal server vittima.
# Sono poche e fisse: e' esattamente cio' che distingue il traffico
# legittimo da uno scan, che ne tocca centinaia.
SERVICE_PORTS = [80, 443, 22, 8080, 3306]

# Dimensioni tipiche di richiesta/risposta per ciascun servizio
PAYLOAD_SIZES = {
    80: (256, 4096),
    443: (512, 8192),
    22: (128, 512),
    8080: (256, 2048),
    3306: (128, 1024),
}

VOIP_PORT = 5060
VOIP_PAYLOAD = 172      # G.711 a 20 ms
VOIP_INTERVAL = 0.02    # 50 pacchetti/s


# ---------------------------------------------------------------------------
# SERVER
# ---------------------------------------------------------------------------
def handle_client(conn, port):
    """Risponde con un payload di dimensione plausibile per il servizio."""
    try:
        data = conn.recv(4096)
        if not data:
            return
        lo, hi = PAYLOAD_SIZES.get(port, (256, 1024))
        conn.sendall(b'x' * random.randint(lo, hi))
    except OSError:
        pass
    finally:
        conn.close()


def tcp_listener(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(('0.0.0.0', port))
    except OSError as e:
        print('[server] impossibile bindare la porta %d: %s' % (port, e))
        return
    srv.listen(16)
    print('[server] in ascolto su TCP/%d' % port)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=handle_client, args=(conn, port),
                         daemon=True).start()


def udp_listener(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    print('[server] in ascolto su UDP/%d' % port)
    while True:
        try:
            srv.recvfrom(2048)
        except OSError:
            break


def run_server():
    for p in SERVICE_PORTS:
        threading.Thread(target=tcp_listener, args=(p,), daemon=True).start()
    threading.Thread(target=udp_listener, args=(VOIP_PORT,),
                     daemon=True).start()
    print('[server] pronto. Ctrl-C per terminare.')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n[server] terminato')


# ---------------------------------------------------------------------------
# CLIENT: flussi TCP con interarrivo esponenziale
# ---------------------------------------------------------------------------
def run_client(target, duration, rate, logfile):
    """
    rate = numero medio di connessioni al secondo.
    L'interarrivo e' esponenziale: il processo di arrivo e' di Poisson,
    come nei modelli di traffico classici. Non usare un intervallo fisso,
    altrimenti il traffico e' innaturalmente regolare e la baseline del
    detector risulta troppo pulita.
    """
    end = time.time() + duration
    rows = []
    n_ok = n_err = 0

    print('[client] verso %s per %ds (~%.1f conn/s)'
          % (target, duration, rate))

    while time.time() < end:
        port = random.choice(SERVICE_PORTS)
        t0 = time.time()
        nbytes = 0
        status = 'ok'
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target, port))
            lo, hi = PAYLOAD_SIZES.get(port, (256, 1024))
            s.sendall(b'q' * random.randint(lo // 4, lo))
            resp = s.recv(8192)
            nbytes = len(resp)
            s.close()
            n_ok += 1
        except OSError as e:
            status = 'err:%s' % type(e).__name__
            n_err += 1

        rtt = (time.time() - t0) * 1000.0
        rows.append({
            'timestamp': '%.6f' % t0,
            'dst': target,
            'dport': port,
            'bytes': nbytes,
            'rtt_ms': '%.3f' % rtt,
            'status': status,
        })

        # interarrivo esponenziale
        time.sleep(random.expovariate(rate))

    if logfile:
        with open(logfile, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print('[client] log salvato in %s' % logfile)

    print('[client] connessioni: %d ok, %d errore' % (n_ok, n_err))


# ---------------------------------------------------------------------------
# CLIENT: flusso UDP costante (VoIP)
# ---------------------------------------------------------------------------
def run_voip(target, duration):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'v' * VOIP_PAYLOAD
    end = time.time() + duration
    sent = 0
    print('[voip] flusso CBR verso %s:%d per %ds'
          % (target, VOIP_PORT, duration))
    while time.time() < end:
        try:
            s.sendto(payload, (target, VOIP_PORT))
            sent += 1
        except OSError:
            pass
        time.sleep(VOIP_INTERVAL)
    print('[voip] inviati %d pacchetti (%.1f kbit/s medi)'
          % (sent, sent * VOIP_PAYLOAD * 8 / duration / 1000.0))


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description='Traffico benigno per NCIs')
    ap.add_argument('mode', choices=('server', 'client', 'voip'))
    ap.add_argument('--target', default='10.0.0.100')
    ap.add_argument('--duration', type=int, default=300)
    ap.add_argument('--rate', type=float, default=2.0,
                    help='connessioni/s medie (solo client)')
    ap.add_argument('--log', default=None)
    args = ap.parse_args()

    if args.mode == 'server':
        run_server()
    elif args.mode == 'client':
        run_client(args.target, args.duration, args.rate, args.log)
    else:
        run_voip(args.target, args.duration)


if __name__ == '__main__':
    sys.exit(main())
