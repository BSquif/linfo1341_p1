import os
import pyshark
from collections import defaultdict
import matplotlib.pyplot as plt
#create global variables

iP6 = 0
iP7 = 0

# Function to check if IP addresses are present in the pcapng file
def check_ip_addresses(file_path):
    global iP6
    global iP7
    ip_count = defaultdict(int)
    capture = pyshark.FileCapture(file_path)
    for packet in capture:
        try:
            src_ip = packet.ip.src
            if src_ip == '46.105.132.156' :
                iP6+=1
                #escape de la boucle
                capture.close()
                return
            if src_ip ==  '46.105.132.157':
                iP7+=1
                #escape de la boucle
                capture.close()
                return
        except AttributeError:
            pass
    capture.close()
    return 

# Function to process directory
def process_directory(directory):
    ip_counts = defaultdict(int)
    for file_name in os.listdir(directory):
        print(file_name)
        if file_name.endswith(".pcapng"):
            file_path = os.path.join(directory, file_name)
            check_ip_addresses(file_path)
    return 

# Function to create disk diagram
def create_disk_diagram():
    global iP6
    global iP7
    labels = ['IP = 46.105.132.156', 'IP = 46.105.132.157']
    sizes = [iP6, iP7]
    colors = ['gold', 'yellowgreen']
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    #plt.title('Proportion of Files Using IP Addresses')
    plt.show()

# Main function
def main():
    directory = "/Users/benjamin_squifflet/ShadowDrive/List"
    process_directory(directory)
    print("IP Address Counts:")
    create_disk_diagram()

if __name__ == "__main__":
    main()

