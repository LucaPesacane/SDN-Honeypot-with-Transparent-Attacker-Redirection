# SDN-based attack detection and transparent honeypot redirection

Project work per il corso di Network and Cloud Infrastructures.

Il controller rileva due tipologie di attacco a partire dai dati che OpenFlow
rende disponibili, e dirotta in modo trasparente il traffico malevolo verso un
honeypot, dove viene osservato. Al cessare dell'attacco le regole scadono e
l'host torna al forwarding ordinario, senza intervento esterno.

## Struttura del repository

```
topology/topology.py      topologia Mininet
controller/controller.py  applicazione Ryu: detection e mitigazione
scripts/                  script di supporto per la simulazione
results/                  catture, log e screenshot degli esperimenti
```

## Topologia

```
   h_att   h_ben1   h_ben2   h_srv                 h_ben3   h_pot
     |       |        |        |                      |       |
    [-------------- s1 ---------------]----------[----- s2 -----]
         SEGMENTO DI PRODUZIONE                  SEGMENTO HONEYPOT
```

Attaccante e vittima sono entrambi su `s1`: il traffico legittimo non
attraversa mai il link inter-switch. L'honeypot è su `s2`, quindi il traffico
compare sul trunk solo quando la redirezione entra in funzione. `h_ben3` è su
`s2` per avere traffico legittimo anche sul trunk.

### Piano di indirizzamento (10.0.0.0/24)

| Host   | IP         | MAC               | Switch : porta | Ruolo          |
|--------|------------|-------------------|----------------|----------------|
| h_att  | 10.0.0.10  | 00:00:00:00:00:10 | s1 : 1         | attaccante     |
| h_ben1 | 10.0.0.11  | 00:00:00:00:00:11 | s1 : 2         | host benigno   |
| h_ben2 | 10.0.0.12  | 00:00:00:00:00:12 | s1 : 3         | host benigno   |
| h_srv  | 10.0.0.100 | 00:00:00:00:01:00 | s1 : 4         | server vittima |
| h_ben3 | 10.0.0.13  | 00:00:00:00:00:13 | s2 : 1         | host benigno   |
| h_pot  | 10.0.0.200 | 00:00:00:00:02:00 | s2 : 2         | honeypot       |

Trunk: `s1-eth5` ↔ `s2-eth3`. Link di accesso 10 Mbit / 1 ms, trunk
20 Mbit / 2 ms. Switch in OpenFlow 1.3, DPID 1 e 2.

## Prerequisiti

```bash
sudo apt install -y mininet openvswitch-switch nmap iperf tcpdump wireshark
pip3 install --user "eventlet==0.33.3" "dnspython>=2.0" ryu
```

Ryu 4.34 importa da eventlet un simbolo rimosso nelle versioni recenti; la
patch seguente è necessaria perché `ryu-manager` si avvii:

```bash
sed -i 's/from eventlet.wsgi import ALREADY_HANDLED/ALREADY_HANDLED = None/' \
    ~/.local/lib/python3.10/site-packages/ryu/app/wsgi.py
```

Rendere eseguibili gli script:

```bash
chmod +x scripts/*.sh
```

## Esecuzione

Pulizia di eventuali residui di sessioni precedenti:

```bash
sudo mn -c
```

Terminale 1 — controller:

```bash
ryu-manager controller/controller.py
```

Terminale 2 — topologia:

```bash
sudo python3 topology/topology.py
```

Dalla CLI di Mininet, aprire i terminali degli host:

```
mininet> xterm h_srv h_pot h_ben1 h_ben2 h_ben3 h_att
```

### Avvio dei servizi

Negli xterm di **h_srv** e **h_pot**:

```bash
../scripts/servers.sh
```

L'honeypot espone gli stessi servizi della vittima: è ciò che rende credibile
il dirottamento, perché l'attaccante ritrova le porte che si aspetta di
trovare invece di trovare tutto chiuso.

### Traffico benigno

Negli xterm di **h_ben1** e **h_ben2**:

```bash
../scripts/client.sh
```

Nell'xterm di **h_ben3**:

```bash
../scripts/voip.sh
```

L'attesa fra una sessione e la successiva è esponenziale, quindi gli arrivi
seguono un processo di Poisson. Con intervalli fissi la baseline risulterebbe
innaturalmente regolare e le soglie derivate sarebbero troppo strette.

Attendere circa due minuti prima di lanciare gli attacchi, in modo che il
traffico legittimo popoli le statistiche.

### Osservazione

Dalla CLI di Mininet, per catturare ai due estremi del percorso:

```
mininet> h_att wireshark -i h_att-eth0 -k &
mininet> h_pot wireshark -i h_pot-eth0 -k &
```

Filtri utili: `tcp.port == 5001` per il traffico TCP, `udp.port == 5010` per
quello UDP. Lo stesso pacchetto compare nelle due finestre con destinazione
`10.0.0.100` e `10.0.0.200` rispettivamente: è la riscrittura degli header
operata dallo switch.

### Attacchi

Nell'xterm di **h_att**, uno alla volta:

```bash
nmap -sS -p 1-6000 10.0.0.100                # port scan
iperf -c 10.0.0.100 -u -p 5010 -b 3M -t 40   # flood volumetrico UDP
iperf -c 10.0.0.100 -p 5001 -t 40            # flood volumetrico TCP
```

Fra un attacco e il successivo attendere il messaggio `RECOVERY` nel log del
controller: un host già in quarantena non viene rivalutato.

Il flood TCP va lanciato **due volte di seguito**. La prima connessione, già
stabilita al momento della mitigazione, viene terminata da un RST; la seconda,
aperta a redirezione attiva, viene dirottata in modo trasparente e completa il
trasferimento.

### Verifica delle regole installate

Da un terminale qualsiasi, mentre la redirezione è attiva (entro 60 s
dall'alert, prima che le regole scadano):

```bash
sudo ~/Pw_NCIS/scripts/rules.sh
```

Su `s1` compaiono le due regole di redirezione a priorità 100 con le azioni
`set_field`; su `s2` l'eccezione dinamica verso l'attaccante, la regola per
l'ARP e il drop di containment.

### Verifica dell'isolamento dell'honeypot

```
mininet> pingall
```

Atteso 22/30: l'honeypot raggiunge solo l'host dirottato, e nessun host di
produzione riesce a raggiungerlo.

### Verifica della trasparenza

Con la redirezione attiva:

```
mininet> h_att nmap -sT -p 5001,5002,5003 10.0.0.100
mininet> h_att arp -n
```

Le porte risultano aperte su `10.0.0.100` e la cache ARP contiene il MAC
autentico della vittima, benché a rispondere sia l'honeypot.

### Chiusura

```
mininet> exit
sudo mn -c
```

## Rilevamento

I due attacchi vengono rilevati su canali OpenFlow diversi e complementari.

| | canale | firma | soglia |
|---|---|---|---|
| port scan | PacketIn | molte porte distinte, volume trascurabile | 20 porte / 5 s |
| flood | FlowStats | rate elevato su poche porte | 500 pkt/s |

Un port scan genera un PacketIn per ogni porta contattata, perché nessuna
trova corrispondenza nella tabella. Un flood a 5-tupla costante genera invece
un solo PacketIn: il traffico successivo resta nel data plane ed è visibile
unicamente attraverso i contatori delle flow entry, letti dal polling
periodico.

Le soglie sono derivate dalla baseline del traffico legittimo: massimo
osservato 5 porte distinte e circa 100 pacchetti/s, con fattori di sicurezza
rispettivamente 4x e 5x.

## Mitigazione

Due flow entry simmetriche a priorità 100 sullo switch di ingresso
dell'attaccante realizzano un NAT bidirezionale: in andata si riscrivono
`ipv4_dst` ed `eth_dst` verso l'honeypot, in ritorno `ipv4_src` ed `eth_src`
con quelli della vittima. L'attaccante invia a 10.0.0.100 e riceve risposte da
10.0.0.100. L'ARP non viene toccato, quindi la sua cache contiene il MAC
autentico della vittima.

Le regole hanno `idle_timeout` di 60 s: cessato l'attacco scadono, lo switch
notifica il controller con `FlowRemoved` e l'host torna al forwarding
ordinario.

## Limiti noti

OpenFlow non può riscrivere i numeri di sequenza TCP. Una sessione TCP già
stabilita al momento della mitigazione viene quindi terminata dall'honeypot
con un RST, che l'attaccante riceve — grazie alla riscrittura del percorso di
ritorno — dall'indirizzo atteso, risultando indistinguibile da una chiusura
del servizio reale. Le connessioni aperte successivamente sono invece
dirottate in modo completamente trasparente. La trasparenza è dunque
per-connessione e non per-host; gli attacchi di ricognizione, costituiti da
connessioni nuove, non sono affetti dal limite.
