from scapy.all import *
import art
from colorama import Fore
import os
import requests
import re
omeglesubnets = re.compile("104.23.*")
# packets = sniff(iface="Ethernet 2", timeout=3, filter="udp && src or dst 192.168.100.243")
# Colored title with art shape
title = art.text2art("OmegleGeo")
print(Fore.BLUE, "-------------------------------------------------------------")
print(Fore.LIGHTBLUE_EX, title)
print(Fore.LIGHTBLACK_EX, "Version 1.0")
print(Fore.WHITE, "Created by: Basil Abdulrahman")
print(Fore.LIGHTMAGENTA_EX, "Linkedin: BasilAbdulrahman")
print(Fore.BLUE, "-------------------------------------------------------------")

#Enables the user to write their local IP address
def inputLocalIP():
    global LIP
    LIP = input('Input your local IP Address (of the NIC in use):\n')
# Methods

# Capture all UDP packets where the source or destination address is the local ip
def initCapture():
    print(Fore.RED, "Capturing...........")
    try:
        packets = sniff(timeout=10,count=30, filter=f"udp && src or dst {LIP}")
    except Exception as e:
        print("Exception of the type: " + str(e))
    wrpcap(filename="init.pcap", pkt=packets)


# Filter distinct IPs from init.pcap
def filterPre():
    packets = rdpcap('init.pcap')
    global preactiveconIP
    preactiveconIP = [LIP]
    for i in packets:
        if i[IP].src not in preactiveconIP:
            preactiveconIP.append(i[IP].src)
    print(Fore.GREEN,"Filtered Successfully.")
    print(f"The IPs of the connection pre-omegle are: {preactiveconIP}")

#Get the IP of the current connection
def getIP():
    global possibleIP
    possibleIP = []
    print(Fore.RED, "Capturing...........")
    packets = sniff(count=5, filter=f"udp && src or dst {LIP}")
    for i in packets:
        if (i[IP].src not in preactiveconIP) and not(omeglesubnets.search(i[IP].src)):
            possibleIP.append(i[IP].src)
            break
    print(f"The possible IPs are: {possibleIP}")


# Deletes pcap file is prompted by user
def deleteInitpcap():
    # res = input('Delete init.pcap?\n')
    # if res.lower() in ["yes", "y"]:
    os.remove('init.pcap')
    #     print(Fore.GREEN, "PCAP File Successfully Deleted.")
    # else:
    #     pass
#Sends requests to ipwho.app with the possible IPs
def getIPlocation():
    print('Locations of possible IPs:\n')
    j=1
    for i in possibleIP:
        print("--------------------------------------------------")
        print(f"IP #{j}: {i}")
        request = requests.get(f"https://ipwhois.app/json/{i}").json()
        print(f"IP Address Type: {request['type']}")
        print(f"Internet Service Provider: {request['isp']}")
        print(f"Country: {request['country']}")
        print(f"Region: {request['region']}")
        print(f"City: {request['city']}")
        print("--------------------------------------------------")
        j+=1
replay=True
inputLocalIP()
initCapture()
print(Fore.YELLOW, "Capturing Completed, filtering active connections...........")
filterPre()
print("Connect to Omegle, in order to proceed.")
print("Waiting for user to prompt.......")
input("Click enter to proceed:")
#Loops trying to get the IP
while replay:
    getIP()
    getIPlocation()
    res = input("Replay?(Click Enter, if no then write (n/no))\n")
    if res.lower() in ["no","n "]:
        replay=False
    else:
        continue
#Deletes the pcap file made in the beginning
deleteInitpcap()

print(Fore.CYAN,"Thank you for using OmegleGeo!, Goodbye!!")