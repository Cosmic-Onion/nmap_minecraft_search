import nmap 
import requests
import re

wanIP32 = requests.get("https://api.ipify.org").text
port = 25565

computer = nmap.PortScanner()
server = nmap.PortScanner()

print("\nSearching 4 deditated wam\n")

print("Your IP:",wanIP32,"\n")

wanIP16 = re.sub("[0-9]*.[0-9]*$","",wanIP32)

print("Checking IP addresses "+wanIP16+"0.0 to "+wanIP16+"255.255\n")

y = 0
z = 0
server_list = []

while y < 256:
    computer.scan(hosts=wanIP16+str(y)+".0/24",arguments="-n -sP -PE -PA 25565")
    print("scanning range: "+wanIP16+str(y)+".0/24")
    computer_list = [x for x in computer.all_hosts()] 
    for host in computer_list:
        try:
            if server.scan(host,str(port))["scan"][host]["tcp"][port]["state"] == "open":
                print("\n"+host+":25565 might be a server!\n")
                server_list.append(host+":25565")
                z = z + 1
        except KeyError:
            continue
    
    y = y + 1

    if y == 100:
        print("\nshodan.io is good for this kinda thing too\n")

print("\n"+z+" open ports found!\n")

for server in server_list:
    print(server)