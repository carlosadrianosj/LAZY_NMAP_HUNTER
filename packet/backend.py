#!/usr/bin/python3

from packet.Class_auto import Auto
from packet.Class_recon import Recon
from packet.Class_scan import Scan
from packet.Class_vuln import Vuln
from packet.Class_screen import Screen
auto = Auto()
recon = Recon()
scan = Scan()
vuln = Vuln()
screen = Screen()


menuOld = []

auto.usuario_root()
def main():
    screen.banner()
    auto.erase_files()
    screen.menu()
    while True:
        command = int(input("Digite Um número |ex: 4 (Opção de menu)|: "))

        if command == 5:
            resetMenu()
            auto.exit()
            break

        if (command == 4):
            screen.menu()
            continue

        levelUm(command)


def setMenuOld(menu):
    global menuOld
    menuOld.append(menu)

def backMenuOld():
    global menuOld
    menuReturn = 4

    if (len(menuOld) == 1):
        screen.menu()
        return menuReturn
    else:
        menuReturn = menuOld[len(menuOld)-2]
        return menuReturn
        
def resetMenu():
    global menuOld
    menuOld = []

def levelUm(command):
    if command == 1:
        setMenuOld(command)
        screen.subMenuUm()
        escolha = str(input("\n\ndigite sua opção |ex: ack|: "))
        if escolha == "ack":
            scan.scan_ack()

        elif escolha == "syn":
            scan.scan_syn()

        elif escolha == "udp":
            scan.scan_udp()

        elif escolha == "arp":
            scan.scan_arp()

        elif escolha == "icmp":
            scan.scan_icmp()

        elif escolha == "sctp":
            scan.scan_sctp()
            
        elif escolha == "ip":
            scan.scan_ip()

        elif escolha == "broad":
            scan.scan_broadcast_ping()

        elif escolha == "sec":
            scan.scan_waf_ips()
               
    elif command == 2:
        setMenuOld(command)
        screen.subMenuDois()
        escolha = str(input("\n\ndigite sua opção |ex: serv|: "))
        if escolha == "serv":
            recon.recon_serv()

        elif escolha == "op":
            recon.recon_OP()

        elif escolha == "http":
            recon.recon_http_methods()

        elif escolha == "smb":
            recon.recon_smb()

        elif escolha == "proxy":
            recon.recon_http_proxy()

        elif escolha == "direct":
            recon.recon_enum_files_directory()
            
        elif escolha == "brute":
            recon.recon_brute_force()

        elif escolha == "xss":
            recon.recon_xss()

        elif escolha == "sqli":
            recon.recon_SQLInjection()

        elif escolha == "git":
            recon.recon_git_exposed()
        
        elif escolha == "shellshock":
            recon.recon_shellshock()

        elif escolha == "ssl":
            recon.recon_SSL()


    elif command == 3:
        setMenuOld(command)
        screen.subMenuTres()
        escolha = str(input("\n\ndigite sua opção |ex: all|: "))
        if escolha == "all":
            vuln.vuln_all()

        elif escolha == "smb":
            vuln.vuln_smb()

        elif escolha == "default":
            vuln.vuln_default_accounts()

        elif escolha == "shellshock":
            vuln.vuln_shellshock()