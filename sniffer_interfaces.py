from scapy.all import get_if_list, get_if_addr

print("\nAvailable Interfaces:\n")

for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
    except:
        ip = "No IP"

    print(f"{iface}  --->  {ip}")