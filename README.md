# Honeypot redirection in ambiente SDN

Rilevamento del traffico malevolo e redirezione trasparente verso un honeypot,
mediante controller Ryu e switch OpenFlow emulati in Mininet.

## Avvio

Terminale 1 — controller:

```bash
ryu-manager controller/controller.py
```

Terminale 2 — topologia:

```bash
sudo python3 topology/topology.py
```

Apertura dei terminali degli host, dalla CLI di Mininet:

```
mininet> xterm h_srv h_pot h_ben1 h_ben2 h_ben3 h_att
```

## Servizi

Su **h_srv** e **h_pot** — espone cinque servizi TCP e uno UDP:

```bash
scripts/servers.sh
```

## Traffico benigno

Su **h_ben1** e **h_ben2** — sessioni TCP:

```bash
scripts/client.sh
```

Su **h_ben3** — flusso UDP:

```bash
scripts/voip.sh
```

## Attacchi

Su **h_att**, uno alla volta, attendendo il messaggio `RECOVERY` nel log del
controller fra un attacco e il successivo:

```bash
nmap -sS -p 1-6000 10.0.0.100                # port scan
iperf -c 10.0.0.100 -u -p 5010 -b 3M -t 40   # flood UDP
iperf -c 10.0.0.100 -p 5001 -t 40            # flood TCP
```

## Verifiche

Regole installate sui due switch, mentre la redirezione è attiva:

```bash
ovs - ofctl -O OpenFlow13 dump - flows s1
```
```bash
ovs - ofctl -O OpenFlow13 dump - flows s2
```

Isolamento dell'honeypot, dalla CLI di Mininet (atteso 20/30):

```
mininet> pingall
```

Cache ARP dell'attaccante — deve contenere il MAC del server reale:

```
mininet> h_att arp -n
```

Cattura del traffico ai due estremi del percorso:

```
mininet> h_att wireshark -i h_att-eth0 -k &
mininet> h_pot wireshark -i h_pot-eth0 -k &
```
