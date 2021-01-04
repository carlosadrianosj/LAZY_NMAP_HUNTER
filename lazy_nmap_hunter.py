#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import os, sys, time
os.system('clear')

#função para reiniciar as placas de rede logo após as consultas
def rede_restart():
    print("\n\nUm momento, estou reiniciando sua placa de rede!\n\n")
    time.sleep(2)
    os.system('sudo systemctl restart NetworkManager.service')


print('\033[35m'+'''
\n\n\n
 ▄█          ▄████████  ▄███████▄  ▄██   ▄                                               
███         ███    ███ ██▀     ▄██ ███   ██▄                                             
███         ███    ███       ▄███▀ ███▄▄▄███                                             
███         ███    ███  ▀█▀▄███▀▄▄ ▀▀▀▀▀▀███                                             
███       ▀███████████   ▄███▀   ▀ ▄██   ███                                             
███         ███    ███ ▄███▀       ███   ███                                             
███▌    ▄   ███    ███ ███▄     ▄█ ███   ███                                             
█████▄▄██   ███    █▀   ▀████████▀  ▀█████▀                                              
▀                                                                                        
          ███▄▄▄▄     ▄▄▄▄███▄▄▄▄      ▄████████    ▄███████▄                            
          ███▀▀▀██▄ ▄██▀▀▀███▀▀▀██▄   ███    ███   ███    ███                            
          ███   ███ ███   ███   ███   ███    ███   ███    ███                            
          ███   ███ ███   ███   ███   ███    ███   ███    ███                            
          ███   ███ ███   ███   ███ ▀███████████ ▀█████████▀                             
          ███   ███ ███   ███   ███   ███    ███   ███                                   
          ███   ███ ███   ███   ███   ███    ███   ███                                   
           ▀█   █▀   ▀█   ███   █▀    ███    █▀   ▄████▀                                 
                                                                                         
                  ▄█    █▄    ███    █▄  ███▄▄▄▄       ███        ▄████████    ▄████████ 
                 ███    ███   ███    ███ ███▀▀▀██▄ ▀█████████▄   ███    ███   ███    ███ 
                 ███    ███   ███    ███ ███   ███    ▀███▀▀██   ███    █▀    ███    ███ 
                ▄███▄▄▄▄███▄▄ ███    ███ ███   ███     ███   ▀  ▄███▄▄▄      ▄███▄▄▄▄██▀ 
               ▀▀███▀▀▀▀███▀  ███    ███ ███   ███     ███     ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   
                 ███    ███   ███    ███ ███   ███     ███       ███    █▄  ▀███████████ 
                 ███    ███   ███    ███ ███   ███     ███       ███    ███   ███    ███ 
                 ███    █▀    ████████▀   ▀█   █▀     ▄████▀     ██████████   ███    ███ 
                                                                              ███    ███              

                       (programador: carlosadrianosj)
             (Ferramenta criada para facilitar comandos com nmap)
                         (Para Opções, digite help)
\n\n\n\
''')

#verifica se o programa foi executado em modo root
permissao_do_usuario = os.geteuid()
if permissao_do_usuario == 1000:
      print("              Este programa precisa ser executado em modo ROOT!!")
      time.sleep(2)
      print("              Este programa precisa ser executado em modo ROOT!!")
      time.sleep(2)
      print("              Este programa precisa ser executado em modo ROOT!!")
      time.sleep(2)
      print("                  Exemplo: sudo python3 lazy_nmap_hunter.py\n\n\n\n")
      time.sleep(2)
      os._exit()
elif permissao_do_usuario == 0:
      pass

#inicia o laço infinito na ferramenta
comando = True
while comando:
    
    #captura a opção digitada pelo usuário
    comando = str(input("LAZY_NMAP_HUNTER> ")) 

    #compara a variável comando com as opções existentes no programa
    if comando == "help": 
        print('''
            
   ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ##    
   #                                                       __COMANDOS__                                                              #
   # help = mostra as opções de comandos                                                                                             #
   # ack = irá executar um ACK scan no escopo                                                                                        #
   # syn = irá executar um SYN scan no escopo                                                                                        #
   # udp = irá executar um UDP scan no escopo                                                                                        #
   # arp = irá executar um ARP scan no escopo                                                                                        #
   # icmp = irá executar um ICMP scan no escopo                                                                                      #
   # sctp = irá executar um SCTP INIT scan no escopo                                                                                 #
   # ip = irá executar um IP scan no escopo (utiliza os seguintes protocolos para varredura: IGMP, IP-in-IP, ICMP, UDP e SCTP)       #
   # serv = irá executar uma varredura nos serviços do escopo                                                                        #
   # op = irá executar uma varredura em busca do sistema operacional do escopo                                                       #
   # http = irá executar uma varredura para verificar quais metodoso escopo aceita                                                   #
   # vuln = irá executar uma varredura em busca de vulnerabilidades no escopo (esta opção executa todos os scripts da categoria vuln)#
   # smb = irá executar uma varredura completa identificando e enumerando vulnerabilidades no SMB                                    #
   # exit = fecha o programa                                                                                                         # 
   #                                                                                                                                 #
   ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ##          
            
            ''')

    elif comando == "ack":
      print("\n\n#############_ACK_SCAN_##############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
      print("\n\n")
      os.system('sudo nmap -sn -PA {}'.format(escopo))
      print("\n\n#####################################\n\n")  
      rede_restart()

    elif comando == "syn":
      print("\n\n#############_SYN_SCAN_##############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
      print("\n\n")
      os.system('sudo nmap -sn -PS {}'.format(escopo))
      print("\n\n#####################################\n\n") 
      rede_restart()

    elif comando == "udp":
      print("\n\n#############_UDP_SCAN_##############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
      print("\n\n")
      os.system('sudo nmap -sn -PU {}'.format(escopo))
      print("\n\n#####################################\n\n") 
      rede_restart()

    elif comando == "arp":
      print("\n\n#############_ARP_SCAN_##############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
      print("\n\n")
      os.system('sudo nmap -sn -PR {}'.format(escopo))
      print("\n\n#####################################\n\n")
      rede_restart()

    elif comando == "icmp":
      print("\n\n#############_ICMP_SCAN_##############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
      print("\n\n")
      os.system('sudo nmap -sn -PE {}'.format(escopo))
      print("\n\n######################################\n\n")
      rede_restart()

    elif comando == "sctp":
      print("\n\n#############_SCTP_SCAN_##############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
      print("\n\n")
      os.system('sudo nmap -sn -PY {}'.format(escopo))
      print("\n\n######################################\n\n")
      rede_restart()


    elif comando == "ip":
      print("\n\n##############_IP_SCAN_##############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
      print("\n\n")
      os.system('sudo nmap -sn -PO {}'.format(escopo))
      print("\n\n#####################################\n\n")
      rede_restart()

    elif comando == "serv":
      print("\n\n############_SERVIÇOS_SCAN_############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
      print("\n\n")
      os.system('sudo nmap -sV --version-intensity 9 {}'.format(escopo))
      print("\n\n#####################################\n\n")
      rede_restart()

    elif comando == "op":
      print("\n\n####################SISTEMA_OPERACIONAL_SCAN_#####################\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
      print("\n\n")
      os.system('sudo nmap -O {}'.format(escopo))
      print("\n\n##################################################################\n\n")
      
      print("#############PROPABILIDADE_SISTEMA_OPERACIONAL_SCAN_##############\n\n")
      os.system('sudo nmap -O --osscan-guess {}'.format(escopo))
      print("\n\n################################################################\n\n")
      rede_restart()

    elif comando == "http":
      print("\n\n#############_HTTP_SCAN_##############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou google.com|: ")
      print("\n\n")
      os.system('sudo nmap -p80 --script http-methods --script-args http-methods.retest {}'.format(escopo))
      print("\n\n#####################################\n\n")
      rede_restart()

    elif comando == "vuln":
      print("\n\n#############_VULN_SCAN_##############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24|: ")
      print("\n\n")
      os.system('sudo nmap -sV --script vuln {}'.format(escopo))
      print("\n\n#####################################\n\n")
      rede_restart()
    
    elif comando == "smb":
      print("\n\n#############_SMB_SCAN_##############\n\n")
      escopo = input("Digite aqui seu alvo|ex: 192.168.0.7 ou 192.168.0.0/24: ")
      print("\n\n")
      print("#Esta opção pode demorar um pouco para retornar resultados, por favor aguarde!#\n\n")
      print("#_Verificando o modo e propriedades do SMB no escopo_#\n\n")
      os.system('sudo nmap -Pn-n -sT -sC -p139,445 {}'.format(escopo))
      print("\n\n#####################################\n\n")

      print("#_Listando compartilhamentos abertos SMB_#\n\n")
      os.system('sudo nmap -Pn --script smb-enum-shares -p 139,445 {}'.format(escopo))
      print("\n\n#####################################\n\n")

      print("#_Tentando listar vulnerabilidades no SMB do escopo_#\n\n")
      os.system('sudo nmap -Pn --script smb-vuln* -p 139,445 {}'.format(escopo))
      print("\n\n#####################################\n\n")
      rede_restart()

    elif comando  == "exit":
      print("\n\nVolte Sempre!!")
      time.sleep(2)
      os.system('clear') 
      break
    
    elif comando  == "":
      print("\n Para comandos, digit help!")
 




