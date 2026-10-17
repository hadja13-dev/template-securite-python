

## Installation

    poetry install

## Utilisation

    poetry run tp1 --pcap capture.pcap --out report.json

Pour le développement, une capture live est possible :

    poetry run tp1 --iface eth0 --count 100 --out report.json

L'outil écrit `report.json` (protocoles, attaques, flag) et `report.pdf`
(graphique, tableau des protocoles, attaques et règles de blocage).

## Détections

- **ARP spoofing** : [comment tu repères l'attaquant : MAC qui revendique plusieurs IP…]
- **Scan de ports** : [SYN seuls, seuil de 15 ports distincts par IP source…]
- **Injection SQL** : [motifs cherchés, uniquement dans les requêtes HTTP…]
- **Flag** : [où et comment tu le cherches, gestion des leurres…]

## Organisation du code

[Une ligne par module : capture, stats, detection/, flag, blocking, report, main.]

## Tests et qualité

    poetry run pytest
    poetry run ruff check .
    poetry run pre-commit run --all-files
