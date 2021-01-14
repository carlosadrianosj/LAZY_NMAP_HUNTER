#!/usr/bin/python3

import os, screen, time, lib_lazy_nmap, auto

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
            lib_lazy_nmap.scan_ack() 

        elif escolha == "syn":
            lib_lazy_nmap.scan_syn()

        elif escolha == "udp":
            lib_lazy_nmap.scan_udp()

        elif escolha == "arp":
            lib_lazy_nmap.scan_arp()

        elif escolha == "icmp":
            lib_lazy_nmap.scan_icmp()

        elif escolha == "sctp":
            lib_lazy_nmap.scan_sctp()
            
        elif escolha == "ip":
            lib_lazy_nmap.scan_ip()

        elif escolha == "broad":
            lib_lazy_nmap.scan_broadcast_ping()

        elif escolha == "sec":
            lib_lazy_nmap.scan_waf_ips()
               
    elif command == 2:
        setMenuOld(command)
        screen.subMenuDois()
        escolha = str(input("\n\ndigite sua opção |ex: serv|: "))
        if escolha == "serv":
            lib_lazy_nmap.recon_serv()

        elif escolha == "op":
            lib_lazy_nmap.recon_OP()

        elif escolha == "http":
            lib_lazy_nmap.recon_http_methods()

        elif escolha == "smb":
            lib_lazy_nmap.recon_smb()

        elif escolha == "proxy":
            lib_lazy_nmap.recon_http_proxy()

        elif escolha == "direct":
            lib_lazy_nmap.recon_enum_files_directory()
            
        elif escolha == "brute":
            lib_lazy_nmap.recon_brute_force()

        elif escolha == "xss":
            lib_lazy_nmap.recon_xss()

        elif escolha == "sqli":
            lib_lazy_nmap.recon_SQLInjection()

        elif escolha == "git":
            lib_lazy_nmap.recon_git_exposed()
        
        elif escolha == "shellshock":
            lib_lazy_nmap.recon_shellshock()

        elif escolha == "ssl":
            lib_lazy_nmap.recon_SSL()


    elif command == 3:
        setMenuOld(command)
        screen.subMenuTres()
        escolha = str(input("\n\ndigite sua opção |ex: all|: "))
        if escolha == "all":
            lib_lazy_nmap.vuln_all()

        elif escolha == "smb":
            lib_lazy_nmap.vuln_smb()

        elif escolha == "default":
            lib_lazy_nmap.vuln_default_accounts()

        elif escolha == "shellshock":
            lib_lazy_nmap.vuln_shellshock()