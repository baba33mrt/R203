from scapy.all import *

ICMPv6_types = {128: 'Echo-Request', 129: 'Echo-Reply', 135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement',
                133: 'Router Solicitation', 134: 'Router Advertisement'} # Dictionnaire qui contient les types de trames ICMPv6


def print_icmpv6(trame): # Fonction qui affiche les informations sur les trames ICMPv6
    print(trame.summary()) # Affiche le résumé de la trame
    type = trame[2].type # Récupère le type de la trame
    if type == 135 or type == 136: # Si c'est une trame de type 135 ou 136
        print(f"TYPE PACKET ICMP {ICMPv6_types[type]}") # Affiche le type de la trame
        print(f"Ethernet: MAC Source	: {trame[0].src}") # Affiche l'adresse MAC source
        print(f"Ethernet: MAC Destination: {trame[0].dst}") # Affiche l'adresse MAC destination
        print(f"IPv6: IP Source: {trame[1].src}") # Affiche l'adresse IP source
        print(f"IPv6: IP Destination: {trame[1].dst}") # Affiche l'adresse IP destination
        print(f"ICMPv6: IP Target: {trame[2].tgt}") # Affiche l'adresse IP cible
        print(f"ICMPv6: MAC Requested: {trame[3].lladdr}") # Affiche l'adresse MAC demandée
        print("\n")
    else:
        print(f"TYPE PACKET ICMP: {ICMPv6_types[type]}") # Affiche le type de la trame
        print(f"Ethernet: MAC Source: {trame[0].src}") # Affiche l'adresse MAC source
        print(f"Ethernet: MAC Destination: {trame[0].dst}") # Affiche l'adresse MAC destination
        print(f"IPv6: IP Source: {trame[1].src}") # Affiche l'adresse IP source
        print(f"IPv6: IP Destination: {trame[1].dst}") # Affiche l'adresse IP destination
        print("\n")


carte = conf.iface # Récupère la carte réseau
print(f"On commence le 'sniffing' sur la carte {carte}:")
print("\n")
sniff(filter="ip6 proto 58", prn=print_icmpv6, store=0, iface=carte, count=6) # Sniff les trames ICMPv6

