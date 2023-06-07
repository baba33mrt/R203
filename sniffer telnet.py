from scapy.all import *

checkports = {20: 'FTP-DATA', 21: 'FTP-CONTROL', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
              110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 3389: 'RDP'}


# capture des données dans les fichiers pcap

alldata = b''  # Données binaires brutes
trames = rdpcap('telnet-total.pcapng')
str = ''
arr = []
for trame in trames:
    try:
        if trame['Ether'].type == 0x0800:
            if trame['TCP'].dport == 23:
                if trame['Raw'].load != b'':  # Donnes binaries brutes
                    data = trame['Raw'].load
                    print(data)
                    if data.startswith(b'\xff'):
                        pass
                    elif data.find(b'\r\x00'):
                        arr.append(str)
                    else:
                        # print(data)
                        data = data.decode('utf-8')
                        str = str + data
    except:
        pass

