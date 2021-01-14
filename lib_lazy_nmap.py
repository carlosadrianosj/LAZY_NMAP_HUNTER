#!/usr/bin/python3

'''
programador: carlosadrianosj
Biblioteca contendo as funções da ferramenta lazy_nmap_hunter.py
Esta biblioteca é open source, sinta-se a vontade para usar em seus projetos
Não se esqueça dos creditos 
'''
import time, os, sys, auto, screen


#############################_Funções de scan de rede_##########################################
#Esta sessão de funções serve para detectar quais dispositivos estão ativos na rede

def scan_ack():
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

def scan_syn():
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

def scan_udp():
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

def scan_arp():
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

def scan_icmp():
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

def scan_sctp():
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

def scan_ip():
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

def scan_broadcast_ping():
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

def scan_waf_ips():
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

################################Funções para verificar host###################################
#Esta sessão de funções serve para enumerar informações sobre dispositivos ativos na rede

def recon_serv():
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

def recon_OP():
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

def recon_http_methods():
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
        os.system('sudo nmap -p- --script http-methods --script-args http-methods.retest {} >> resultados_lazy_nmap/recon_http.txt'.format(escopo))
        os.system('cat resultados_lazy_nmap/recon_http.txt')
        screen.jogo_da_velha()  
        auto.rede_restart()

def recon_smb():
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

def recon_http_proxy():
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

def recon_enum_files_directory():
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
            os.system('\n\nsudo nmap --script http-enum --script-args http-enum.basepath={} -p80 {}'.format(caminho, escopo))
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
            os.system('\n\nsudo nmap --script http-enum --script-args http-enum.basepath={} -p80 {} >> resultados_lazy_nmap/recon_direct.txt'.format(caminho, escopo))
            os.system('cat resultados_lazy_nmap/recon_direct.txt')
            screen.jogo_da_velha()  
            auto.rede_restart()

def recon_brute_force():
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
            os.system('\n\nsudo nmap -p80 --script http-brute {} >> resultados_lazy_nmap/recon_brute.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_brute.txt')
            screen.jogo_da_velha()  
            auto.rede_restart()

        elif decide == "2":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            os.system('\n\nsudo nmap -p80 --script http-wordpress-brute {} >> resultados_lazy_nmap/recon_brute.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_brute.txt')
            screen.jogo_da_velha()  
            auto.rede_restart()

        elif decide == "3":
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
            os.system('\n\nsudo nmap -p80 --script http-joomla-brute {} >> resultados_lazy_nmap/recon_brute.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_brute.txt')
            screen.jogo_da_velha()  
            auto.rede_restart()

def recon_xss():
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
            os.system('sudo nmap -p80 --script http-unsafe-output-escaping {} >> resultados_lazy_nmap/recon_xss.txt'.format(escopo))
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
            os.system('sudo nmap -p80 --script http-phpself-xss,http-unsafe-output-escaping {} >> resultados_lazy_nmap/recon_xss.txt'.format(escopo))
            os.system('cat resultados_lazy_nmap/recon_xss.txt')
            screen.jogo_da_velha()  
            auto.rede_restart()

def recon_SQLInjection():
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

def recon_git_exposed():
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

def recon_shellshock():
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
        os.system('sudo nmap -sV --script http-shellshock {} >> resultados_lazy_nmap/recon_shellshock.txt'.format(escopo))
        os.system('cat resultados_lazy_nmap/recon_shellshock.txt')
        screen.jogo_da_velha()  
        auto.rede_restart()

def recon_SSL():
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

##############################Funções de enumeração de vulnerabilidades#################################
#Esta sessão de funções é voltado a detecção e exploração de vulnerabilidades

def vuln_all():
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

def vuln_smb():
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
        os.system('sudo nmap -Pn --script smb-enum-shares -p 139,445 {} >> resultados_lazy_nmap/vuln_smb.txt'.format(escopo))
        screen.jogo_da_velha()  

        print("#_Tentando listar vulnerabilidades no SMB do escopo_#\n\n")
        os.system('sudo nmap -Pn --script smb-vuln* -p 139,445 {} >> resultados_lazy_nmap/vuln_smb.txt'.format(escopo))
        os.system('cat resultados_lazy_nmap/vuln_smb.txt')
        screen.jogo_da_velha()  
        auto.rede_restart()

def vuln_default_accounts():
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
            os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=web {}'.format(escopo))
            screen.jogo_da_velha()  
            auto.rede_restart()

        elif decide == "2":
            print("\n\n#############_ROTEADORES_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
            escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
            os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=routers {}'.format(escopo))
            screen.jogo_da_velha()  
            auto.rede_restart()

        elif decide == "3":
                print("\n\n#############_DISPOSITIVOS_SEGURANÇA_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=security {}'.format(escopo))
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "4":
                print("\n\n#############_SISTEMAS INDUSTRIAIS_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=industrial {}'.format(escopo))
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "5":
                print("\n\n#############_IMPRESSORAS_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=printer {}'.format(escopo))
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "6":
                print("\n\n#############_DISPOSITIVOS_ARMAZENAMENTO_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=storage {}'.format(escopo))
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "7":
                print("\n\n#############_VIRTUALIZAÇÃO_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=virtualization {}'.format(escopo))
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "8":
                print("\n\n#############_CONSOLE_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=console {}'.format(escopo))
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
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=web {} >> resultados_lazy_nmap/vuln_default.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')            
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "2":
                print("\n\n#############_ROTEADORES_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=routers {} >> resultados_lazy_nmap/vuln_default.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "3":
                print("\n\n#############_DISPOSITIVOS_SEGURANÇA_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=security {} >> resultados_lazy_nmap/vuln_default.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "4":
                print("\n\n#############_SISTEMAS INDUSTRIAIS_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=industrial {} >> resultados_lazy_nmap/vuln_default.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "5":
                print("\n\n#############_IMPRESSORAS_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=printer {} >> resultados_lazy_nmap/vuln_default.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "6":
                print("\n\n#############_DISPOSITIVOS_ARMAZENAMENTO_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=storage {} >> resultados_lazy_nmap/vuln_default.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "7":
                print("\n\n#############_VIRTUALIZAÇÃO_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=virtualization {} >> resultados_lazy_nmap/vuln_default.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "8":
                print("\n\n#############_CONSOLE_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=console {} >> resultados_lazy_nmap/vuln_default.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()  
                auto.rede_restart()

        elif decide == "9":
                print("\n\n#############_TODAS_OPÇÕES_DEFAULT_ACCOUNTS_SCAN_##############\n\n")
                escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
                os.system('\n\nsudo nmap -p80 --script http-default-accounts {} >> resultados_lazy_nmap/vuln_default.txt'.format(escopo))
                os.system('cat resultados_lazy_nmap/vuln_default.txt')
                screen.jogo_da_velha()  
                auto.rede_restart()

def vuln_shellshock():
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
        os.system('sudo nmap -sV --script http-shellshock --script-args cmd={} {} >> resultados_lazy_nmap/vuln_shellshock.txt'.format(comando, escopo))
        os.system('cat resultados_lazy_nmap/vuln_shellshock.txt')
        screen.jogo_da_velha()  
        auto.rede_restart()

