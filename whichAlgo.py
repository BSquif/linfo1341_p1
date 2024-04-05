import pyshark
# #open WaitingWithoutSync.pcapng
files = ["./Add10FileWifi.pcapng", "./fullDeleteChrome.pcapng", "./fullChrome.pcapng"]
for file in files :
    cap = pyshark.FileCapture(file)
    # #initialize the counters

    def sizeof(packet):
        return int(packet.length)
    #find the algorithm used for the encryption in TLSv1.3
    for packet in cap:
        #check if 46.105.132.156 or 46.105.132.157 is in the communication
        if 'IP' in packet:
            if packet.ip.addr == '46.105.132.156' or packet.ip.addr == '46.105.132.157' :
                if 'TLS' in packet:
                    #print(packet.tls.get('tls.handshake.type'))
                    if((packet.tls.get('tls.handshake.CipherSuite'))!=None):
                        print(packet.tls.get('tls.handshake.CipherSuite'))
    cap.close()
    
