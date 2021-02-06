#!/usr/bin/python3

import time
import os
import sys
#############################Funções de automação do codigo##########################
#Esta sessão de funções serve para manejo e automação do código

class Auto:
    def __init__(self):
        pass

    def rede_restart(self):
        print("\n\nUm momento, estou reiniciando sua placa de rede!\n\n")
        time.sleep(2)
        os.system('sudo systemctl restart NetworkManager.service')

    def usuario_root(self, permissao_do_usuario=os.geteuid()):

        if permissao_do_usuario != 0:
            for i in range(5):
                print("\n\n              Este programa precisa ser executado em modo ROOT!!\n\n")
                time.sleep(0.5)
            print("                 Exemplo: sudo python3 lazy_nmap_hunter.py")
            sys.exit()
        else:
            pass


    def exit(self):
        time.sleep(0.5)
        print("\n\nVolte Sempre!!")
        time.sleep(2)
        os.system('clear')
        sys.exit()

    def erase_files(self):
        decide = input("Você deseja resetar os scans anteriores (y/n): ")
        if decide == "y":
            arquivos_scans = ["scan_ack.txt", "scan_syn.txt", "scan_udp.txt", "scan_arp.txt", "scan_icmp.txt",
         "scan_sctp.txt", "scan_ip.txt","scan_broad.txt", "scan_sec.txt", "recon_serv.txt", "recon_op.txt",
         "recon_http.txt", "recon_smb.txt", "recon_proxy.txt", "recon_direct.txt", "recon_brute.txt",
         "recon_xss.txt", "recon_sqli.txt", "recon_git.txt", "recon_shellshock.txt", "recon_ssl.txt",
         "vuln_all.txt", "vuln_smb.txt", "vuln_default.txt", "vuln_shellshock.txt"]
            for i in arquivos_scans:
                pwd = os.getcwd()
                file = open("{}/resultados_lazy_nmap/{}".format(pwd, i), "r+")
                file.truncate(0)
                file.close()

        if decide == "n":
            pass