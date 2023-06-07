from scapy.all import *

trames = rdpcap("ping.pcapng")

chesktpes = {0x0806: 'ARP', 0x0800: 'IPv4'}
arptype = {1: 'Request', 2: 'Reply'}


# capture des données dans les fichiers pcap
# print("La capture comprend les paquets suivants :\n")
# for trame in trames:
#     if trame['Ether'].type == 0x0800:
#         # trame.show()
#         print(f"Type de trame : {chesktpes[trame['Ether'].type]}")
#         print(f"Adresse MAC source : {trame['Ether'].src}")
#         print(f"Adresse MAC destination : {trame['Ether'].dst}")
#         print(f"Adresse IP source : {trame['IP'].src}")
#         print(f"Adresse IP destination : {trame['IP'].dst}")
#         print("\n")
#
#     elif trame['Ether'].type == 0x0806:
#         trame.show()
#         print(f"Type de trame : {chesktpes[trame['Ether'].type]}")
#         print(f"Type de demande : {arptype[trame['ARP'].op]}")
#         print(f"Adresse MAC source : {trame['Ether'].src}")
#         print(f"Adresse MAC destination : {trame['Ether'].dst}")
#         print(f"Adresse IP source : {trame['ARP'].psrc}")
#         print(f"Adresse IP destination : {trame['ARP'].pdst}")
#         print("\n")


def capture(trame):
    if trame['Ether'].type == 0x0800:
        # trame.show()
        print(f"Type de trame : {chesktpes[trame['Ether'].type]}")
        print(f"Adresse MAC source : {trame['Ether'].src}")
        print(f"Adresse MAC destination : {trame['Ether'].dst}")
        print(f"Adresse IP source : {trame['IP'].src}")
        print(f"Adresse IP destination : {trame['IP'].dst}")
        print("\n")

    elif trame['Ether'].type == 0x0806:
        trame.show()
        print(f"Type de trame : {chesktpes[trame['Ether'].type]}")
        print(f"Type de demande : {arptype[trame['ARP'].op]}")
        print(f"Adresse MAC source : {trame['Ether'].src}")
        print(f"Adresse MAC destination : {trame['Ether'].dst}")
        print(f"Adresse IP source : {trame['ARP'].psrc}")
        print(f"Adresse IP destination : {trame['ARP'].pdst}")
        print("\n")


carte = conf.iface
print(f"Sniffing on {carte} \n {sniff(filter='ip', iface=carte, prn=capture, store=0, count=100)}")
