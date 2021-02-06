
#!/usr/bin/python3

'''
programador: carlosadrianosj
'''

import os
import time
from packet.Class_auto import Auto
from packet.Class_screen import Screen
auto = Auto()
screen = Screen()

################################Funções para verificar host###################################
# Esta sessão de funções serve para enumerar informações sobre dispositivos ativos na rede
class Recon:
    def __init__(self):
        pass

    def recon_serv(self):
        print("\n\n############_SERVIÇOS_SCAN_############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sV --version-intensity 9 {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -sV --version-intensity 9 {} >> resultados_lazy_nmap/recon_serv.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_serv.txt')
            screen.jogo_da_velha()
            auto.rede_restart()


    def recon_OP(self):
        print("\n\n####################SISTEMA_OPERACIONAL_SCAN_#####################\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('\n\nsudo nmap -O {}'.format(escopo))
            time.sleep(2)
            print("\n\n\n")
            os.system('sudo nmap -O --osscan-guess {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('\n\nsudo nmap -O {} >> resultados_lazy_nmap/recon_op.txt'.format(escopo))
            time.sleep(2)
            print("\n\n\n")
            os.system('sudo nmap -O --osscan-guess {} >> resultados_lazy_nmap/recon_op.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_op.txt')
            screen.jogo_da_velha()
            auto.rede_restart()


    def recon_http_methods(self):
        print("\n\n#############_HTTP_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -p- --script http-methods --script-args http-methods.retest {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system(
                'sudo nmap -p- --script http-methods --script-args http-methods.retest {} >> resultados_lazy_nmap/recon_http.txt'.format(
                    escopo))
            os.system('cat resultados_lazy_nmap/recon_http.txt')
            screen.jogo_da_velha()
            auto.rede_restart()


    def recon_smb(self):
        print("\n\n#############_SMB_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n#Esta opção pode demorar um pouco para retornar resultados, por favor aguarde!#\n\n")
            print("#_Verificando o modo e propriedades do SMB no escopo_#\n\n")
            print("\n\n\n")
            os.system('sudo nmap -Pn-n -sT -sC -p139,445 {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n#Esta opção pode demorar um pouco para retornar resultados, por favor aguarde!#\n\n")
            print("#_Verificando o modo e propriedades do SMB no escopo_#\n\n")
            print("\n\n\n")
            os.system('sudo nmap -Pn-n -sT -sC -p139,445 {} >> resultados_lazy_nmap/recon_smb.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_smb.txt')
            screen.jogo_da_velha()
            auto.rede_restart()


    def recon_http_proxy(self):
        print("\n\n#############_PROXY_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap --script http-open-proxy -p- {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap --script http-open-proxy -p- {} >> resultados_lazy_nmap/recon_proxy.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_proxy.txt')
            screen.jogo_da_velha()
            auto.rede_restart()


    def recon_enum_files_directory(self):
        print("\n\n#############_FILES_DIRECTORY_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            decide = input("Você deseja utilizar uma wordlist personalizada (y/n)? ")
            if decide == "n":
                escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                os.system('\n\nsudo nmap --script http-enum -p- {}'.format(escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "y":
                caminho = input("Digite aqui o caminho da wordlist (ex:/home/caminho/wordlist.txt): ")
                escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                os.system(
                    '\n\nsudo nmap --script http-enum --script-args http-enum.basepath={} -p80 {}'.format(caminho, escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

        elif decide == "y":
            decide = input("Você deseja utilizar uma wordlist personalizada (y/n)? ")
            if decide == "n":
                escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                os.system('\n\nsudo nmap --script http-enum -p- {}>> resultados_lazy_nmap/recon_direct.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/recon_direct.txt')
                screen.jogo_da_velha()
                auto.rede_restart()
            elif decide == "y":
                caminho = input("Digite aqui o caminho da wordlist (ex:/home/caminho/wordlist.txt): ")
                escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                os.system(
                    '\n\nsudo nmap --script http-enum --script-args http-enum.basepath={} -p80 {} >> resultados_lazy_nmap/recon_direct.txt'.format(
                        caminho, escopo))
                os.system('cat resultados_lazy_nmap/recon_direct.txt')
                screen.jogo_da_velha()
                auto.rede_restart()


    def recon_brute_force(self):
        print("\n\n#############_BRUTE_FORCE_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            print('''
                            _OPÇÕES_BRUTE_FORCE_
    
                1 - http = Executará um brute force em busca de enumerar usuários do http
                2 - wordpress = Executará um brute force em busca de enumerar usuários do wordpress
                3 - joomla = Executará um brute force em busca de enumerar usuários do joomla
    
            \n\n
            ''')
            decide = input("Escolha sua opção (ex: 1): ")
            if decide == "1":
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                os.system('\n\nsudo nmap -p80 --script http-brute {}'.format(escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "2":
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                os.system('\n\nsudo nmap -p80 --script http-wordpress-brute {}'.format(escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "3":
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                os.system('\n\nsudo nmap -p80 --script http-joomla-brute {}'.format(escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

        if decide == "y":
            print('''
                            _OPÇÕES_BRUTE_FORCE_
    
                1 - http = Executará um brute force em busca de enumerar usuários do http
                2 - wordpress = Executará um brute force em busca de enumerar usuários do wordpress
                3 - joomla = Executará um brute force em busca de enumerar usuários do joomla
    
            \n\n
            ''')
            decide = input("Escolha sua opção (ex: 1): ")
            if decide == "1":
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-brute {} >> resultados_lazy_nmap/recon_brute.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/recon_brute.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "2":
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                os.system(
                    '\n\nsudo nmap -p80 --script http-wordpress-brute {} >> resultados_lazy_nmap/recon_brute.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/recon_brute.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "3":
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                os.system('\n\nsudo nmap -p80 --script http-joomla-brute {} >> resultados_lazy_nmap/recon_brute.txt'.format(
                    escopo))
                os.system('cat resultados_lazy_nmap/recon_brute.txt')
                screen.jogo_da_velha()
                auto.rede_restart()


    def recon_xss(self):
        print("\n\n#############_XSS_SCAN_##############\n\n")
        print('''
                              _OPÇÕES_XSS_
    
            1 - xss = Executará uma busca afim de enumerar cross site script com pesquisas padronizadas do nmap
            2 - xss_php = Executará uma busca afim de enumerar cross site script com pesquisas focadas em sistemas php    
        \n\n
        ''')
        decide = input("Escolha sua opção (ex: 1): ")
        if decide == "1":
            decide = str(input("\n\nDeseja salvar o resultado (y/n)? "))
            if decide == "n":
                print("\n\n#############_XSS_PADRÃO_SCAN_##############\n\n")
                escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                print("\n\n\n")
                os.system('sudo nmap -p80 --script http-unsafe-output-escaping {}'.format(escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "y":
                print("\n\n#############_XSS_PADRÃO_SCAN_##############\n\n")
                escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                print("\n\n\n")
                os.system(
                    'sudo nmap -p80 --script http-unsafe-output-escaping {} >> resultados_lazy_nmap/recon_xss.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/recon_xss.txt')
                screen.jogo_da_velha()
                auto.rede_restart()

        elif decide == "2":
            decide = str(input("Deseja salvar o resultado (y/n)? "))
            if decide == "n":
                print("\n\n#############_XSS_PHP_SCAN_##############\n\n")
                escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                print("\n\n\n")
                os.system('sudo nmap -p80 --script http-phpself-xss,http-unsafe-output-escaping {}'.format(escopo))
                screen.jogo_da_velha()
                auto.rede_restart()

            elif decide == "y":
                print("\n\n#############_XSS_PHP_SCAN_##############\n\n")
                escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
                print("\n\n\n")
                os.system(
                    'sudo nmap -p80 --script http-phpself-xss,http-unsafe-output-escaping {} >> resultados_lazy_nmap/recon_xss.txt'.format(
                        escopo))
                os.system('cat resultados_lazy_nmap/recon_xss.txt')
                screen.jogo_da_velha()
                auto.rede_restart()


    def recon_SQLInjection(self):
        print("\n\n#############_SQL_INJECTION_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -p80 --script http-sql-injection {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -p80 --script http-sql-injection {} >> resultados_lazy_nmap/recon_sqli.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_sqli.txt')
            screen.jogo_da_velha()
            auto.rede_restart()


    def recon_git_exposed(self):
        print("\n\n#############_GIT_EXPOSED_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -p- --script http-git {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("\n\nDigite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            print("\n\n\n")
            os.system('sudo nmap -p- --script http-git {} >> resultados_lazy_nmap/recon_git.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_git.txt')
            screen.jogo_da_velha()
            auto.rede_restart()


    def recon_shellshock(self):
        print("\n\n#############_SHELLSHOCK_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -sV --script http-shellshock {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system(
                'sudo nmap -sV --script http-shellshock {} >> resultados_lazy_nmap/recon_shellshock.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_shellshock.txt')
            screen.jogo_da_velha()
            auto.rede_restart()


    def recon_SSL(self):
        print("\n\n#############_SSL_SCAN_##############\n\n")
        decide = str(input("Deseja salvar o resultado (y/n)? "))
        if decide == "n":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -p443 --script ssl* {}'.format(escopo))
            screen.jogo_da_velha()
            auto.rede_restart()

        elif decide == "y":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            print("\n\n\n")
            os.system('sudo nmap -p443 --script ssl* {} >> resultados_lazy_nmap/recon_ssl.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_ssl.txt')
            screen.jogo_da_velha()
            auto.rede_restart()