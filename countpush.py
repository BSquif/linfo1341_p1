import pyshark
# #open WaitingWithoutSync.pcapng
cap = pyshark.FileCapture('/Users/benjamin_squifflet/Documents/EPL/Q6/reseaux/AddingAFileEthernet.pcapng')
# #initialize the counters
secured = 0
unsecured = 0
def sizeof(packet):
    return int(packet.length)
# #iterate through the packets and count the isze of the packet when there is a layer TCP versus when there is a layer TCP and a layer TLS
for packet in cap:
    if 'TCP' in packet:
        if 'TLS' in packet:
            secured += sizeof(packet)
        else:
            unsecured += sizeof(packet)

# #print the results
print("Secured bytes: ", secured)
print("Unsecured bytes : ", unsecured)