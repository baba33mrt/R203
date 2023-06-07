from scapy.all import *

checkports = {20: 'FTP-DATA', 21: 'FTP-CONTROL', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
              110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 3389: 'RDP'}


# capture des données dans les fichiers pcap

def fromPcap(file):
    trames = rdpcap(file)
    for trame in trames:
        try:
            if trame['Ether'].type == 0x0800:
                # trame.show()
                if trame['TCP'].dport == 21 or trame['TCP'].sport == 21:
                    # trame.show()
                    if trame['Raw'].load != '':
                        # print(f"Type de trame : {checkports[trame['TCP'].dport]}")
                        data = trame['Raw'].load.decode('utf-8')
                        if data.find('USER') != -1:
                            print(
                                f"Tentative de connexion a un serveur FTP...\nIP source\t: {trame['IP'].src}\nIP destination\t: {trame['IP'].dst}\n=====================")
                            print(f"USER : {data.split(' ')[1]}")
                        if data.find('PASS') != -1:
                            print(f"Mot de passe : {data.split(' ')[1]}")
                        if data.find('230') != -1:
                            print(f"Connexion reussie !")
                            print(f"=====================")

        except:
            pass


# fonction de capture des données en temps réel
def capture(trame):
    try:
        if trame['Ether'].type == 0x0800:
            # trame.show()
            if trame['TCP'].dport == 21 or trame['TCP'].sport == 21:
                # trame.show()
                if trame['Raw'].load != '':
                    # print(f"Type de trame : {checkports[trame['TCP'].dport]}")
                    data = trame['Raw'].load.decode('utf-8')
                    if data.find('USER') != -1:
                        print(
                            f"Tentative de connexion a un serveur FTP...\nIP source\t: {trame['IP'].src}\nIP destination\t: {trame['IP'].dst}\n=====================")
                        print(f"USER : {data.split(' ')[1]}")
                    if data.find('PASS') != -1:
                        print(f"Mot de passe : {data.split(' ')[1]}")
                    if data.find('230') != -1:
                        print(f"Connexion reussie !")
                        print(f"=====================")

    except:
        pass

fromPcap('ftp-total.pcapng')
# card = conf.iface
# print(f"Sniffing on {card} \n {sniff(filter='ip', iface=card, prn=capture, store=0, count=100)}")
