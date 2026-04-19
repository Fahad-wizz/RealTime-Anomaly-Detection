from scapy.all import get_if_list

print("Available Interfaces:\n")

for iface in get_if_list():
    print(iface)