#!/usr/bin/python3

'''
programador: carlosadrianosj
'''

import os
from packet.Class_auto import Auto
from packet.Class_screen import Screen
auto = Auto()
screen = Screen()

##############################Funções de enumeração de vulnerabilidades#################################
# Esta sessão de funções é voltado a detecção e exploração de vulnerabilidades
class Vuln:
    def __init__(self):
        pass

    def vuln_all(self):
        print("\n\n#############_VULN_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -sV --script vuln {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -sV --script vuln {} >> resultados_lazy_nmap/vuln_all.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/vuln_all.txt')
            screen.jogo_da_velha()
            auto.rede_restart()


    def vuln_smb(self):
        print("\n\n#############_SMB_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24: ")
            print("\n\n#_Listando compartilhamentos abertos SMB_#\n\n")
            os.system('sudo nmap -Pn --script smb-enum-shares -p 139,445 {}'.format(escopo))
            screen.jogo_da_velha()

            print("#_Tentando listar vulnerabilidades no SMB do escopo_#\n\n")
            os.system('sudo nmap -Pn --script smb-vuln* -p 139,445 {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24: ")
            print("\n\n#_Listando compartilhamentos abertos SMB_#\n\n")
            os.system(
                'sudo nmap -Pn --script smb-enum-shares -p 139,445 {} >> resultados_lazy_nmap/vuln_smb.txt'.format(escopo))
            screen.jogo_da_velha()

            print("#_Tentando listar vulnerabilidades no SMB do escopo_#\n\n")
            os.system('sudo nmap -Pn --script smb-vuln* -p 139,445 {} >> resultados_lazy_nmap/vuln_smb.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/vuln_smb.txt')
            screen.jogo_da_velha()
            auto.rede_restart()


    def vuln_default_accounts(self):

        print("\n\n#############_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            print('''
                                _OPÇÕES_DEFAULT_ACCOUNTS_
    
                1 - Aplicações Web
                2 - Roteadores
                3 - Dispositivos de segurança
                4 - Sistemas Industriais
                5 - Impressoras e servidores de Impressão
                6 - Dispositivos de armazenamento 
                7 - Sistemas virtualizados
                8 - Consoles remotos 
                9 - Todas as alternativas 
            \n\n
            ''')
            decide = input("Escolha sua opção (ex: 1): ")
            if decide == "1":

                print("\n\n#############_WEB_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=web {}'.format(
                        escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "2":
                print("\n\n#############_ROTEADORES_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=routers {}'.format(
                        escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "3":
                print("\n\n#############_DISPOSITIVOS_SEGURANÇA_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=security {}'.format(
                        escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "4":
                print("\n\n#############_SISTEMAS INDUSTRIAIS_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=industrial {}'.format(
                        escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "5":
                print("\n\n#############_IMPRESSORAS_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=printer {}'.format(
                        escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "6":
                print("\n\n#############_DISPOSITIVOS_ARMAZENAMENTO_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=storage {}'.format(
                        escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "7":
                print("\n\n#############_VIRTUALIZAÇÃO_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=virtualization {}'.format(
                        escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "8":
                print("\n\n#############_CONSOLE_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=console {}'.format(
                        escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "9":
                print("\n\n#############_TODAS_OPÇÕES_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts {}'.format(escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

        elif decide == "y":
            print('''
                                _OPÇÕES_DEFAULT_ACCOUNTS_
    
                1 - Aplicações Web
                2 - Roteadores
                3 - Dispositivos de segurança
                4 - Sistemas Industriais
                5 - Impressoras e servidores de Impressão
                6 - Dispositivos de armazenamento 
                7 - Sistemas virtualizados
                8 - Consoles remotos 
                9 - Todas as alternativas 
            \n\n
            ''')
            decide = input("Escolha sua opção (ex: 1): ")
            if decide == "1":
                print("\n\n#############_WEB_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=web {} >> resultados_lazy_nmap/vuln_default.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "2":
                print("\n\n#############_ROTEADORES_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=routers {} >> resultados_lazy_nmap/vuln_default.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "3":
                print("\n\n#############_DISPOSITIVOS_SEGURANÇA_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=security {} >> resultados_lazy_nmap/vuln_default.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "4":
                print("\n\n#############_SISTEMAS INDUSTRIAIS_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=industrial {} >> resultados_lazy_nmap/vuln_default.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "5":
                print("\n\n#############_IMPRESSORAS_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=printer {} >> resultados_lazy_nmap/vuln_default.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "6":
                print("\n\n#############_DISPOSITIVOS_ARMAZENAMENTO_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=storage {} >> resultados_lazy_nmap/vuln_default.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "7":
                print("\n\n#############_VIRTUALIZAÇÃO_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=virtualization {} >> resultados_lazy_nmap/vuln_default.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "8":
                print("\n\n#############_CONSOLE_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=console {} >> resultados_lazy_nmap/vuln_default.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "9":
                print("\n\n#############_TODAS_OPÇÕES_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-default-accounts {} >> resultados_lazy_nmap/vuln_default.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()
                auto.rede_restart()


    def vuln_shellshock(self):
        print("\n\n#############_SHELLSHOCK_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            comando = input("\n\nDigite o comando que deseja executar no host (ex: nc -nvlp 2222): ")
            print("\n\n\n")
            os.system('sudo nmap -sV --script http-shellshock --script-args cmd={} {}'.format(comando, escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            comando = input("\n\nDigite o comando que deseja executar no host (ex: nc -nvlp 2222): ")
            print("\n\n\n")
            os.system(
                'sudo nmap -sV --script http-shellshock --script-args cmd={} {} >> resultados_lazy_nmap/vuln_shellshock.txt'.format(
                    comando, escopo))
            os.system('cat resultados_lazy_nmap/vuln_shellshock.txt')
            screen.jogo_da_velha()
            auto.rede_restart()
