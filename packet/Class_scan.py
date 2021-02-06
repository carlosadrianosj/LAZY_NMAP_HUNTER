#!/usr/bin/python3

'''
programador: carlosadrianosj
'''

import os
from packet.Class_auto import Auto
from packet.Class_screen import Screen
auto = Auto()
screen = Screen()

class Scan:
    def __init__(self):
        pass

    def scan_ack(self):
        print("\n\n#############_ACK_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PA {}'.format(escopo))

            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PA {} >> resultados_lazy_nmap/scan_ack.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/scan_ack.txt')
            screen.jogo_da_velha()
            auto.rede_restart()

    def scan_syn(self):
        print("\n\n#############_SYN_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PS {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PS {} >> resultados_lazy_nmap/scan_syn.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/scan_syn.txt')
            screen.jogo_da_velha()
            auto.rede_restart()

    def scan_udp(self):
        print("\n\n#############_UDP_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PU {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PU {} >> resultados_lazy_nmap/scan_udp.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/scan_udp.txt')
            screen.jogo_da_velha()
            auto.rede_restart()

    def scan_arp(self):
        print("\n\n#############_ARP_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PR {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PR {} >> resultados_lazy_nmap/scan_arp.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/scan_arp.txt')
            screen.jogo_da_velha()
            auto.rede_restart()

    def scan_icmp(self):
        print("\n\n#############_ICMP_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PE {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PE {} >> resultados_lazy_nmap/scan_icmp.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/scan_icmp.txt')
            screen.jogo_da_velha()
            auto.rede_restart()

    def scan_sctp(self):
        print("\n\n#############_SCTP_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PY {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PY {} >> resultados_lazy_nmap/scan_sctp.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/scan_sctp.txt')
            screen.jogo_da_velha()
            auto.rede_restart()

    def scan_ip(self):
        print("\n\n##############_IP_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PO {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn -PO {} >> resultados_lazy_nmap/scan_ip.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/scan_ip.txt')
            screen.jogo_da_velha()
            auto.rede_restart()

    def scan_broadcast_ping(self):
        print("\n\n#############_BROADCAST_PING_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn --script broadcast-ping {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -sn --script broadcast-ping {} >> resultados_lazy_nmap/scan_broad.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/scan_broad.txt')
            screen.jogo_da_velha()
            auto.rede_restart()

    def scan_waf_ips(self):
        print("\n\n#############_WAF_IPS_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -p80 --script http-waf-detect,http-waf-fingerprint {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -p80 --script http-waf-detect,http-waf-fingerprint {} >> resultados_lazy_nmap/scan_sec.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/scan_sec.txt')
            screen.jogo_da_velha()
            auto.rede_restart()
