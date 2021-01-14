#!/usr/bin/python3

import os, sys, time

def banner():
    os.system('clear')
    time.sleep(0.5)  
    print('\033[35m'+'''
 ▄█          ▄████████  ▄███████▄  ▄██   ▄                                               
███         ███    ███ ██▀     ▄██ ███   ██▄                                             
███         ███    ███       ▄███▀ ███▄▄▄███                                             
███         ███    ███  ▀█▀▄███▀▄▄ ▀▀▀▀▀▀███                                             
███       ▀███████████   ▄███▀   ▀ ▄██   ███                                             
███         ███    ███ ▄███▀       ███   ███                                             
███▌    ▄   ███    ███ ███▄     ▄█ ███   ███                                             
█████▄▄██   ███    █▀   ▀████████▀  ▀█████▀                                              
▀                                                                                        
''')  
    time.sleep(0.5)
    print('\033[35m'+'''
          ███▄▄▄▄     ▄▄▄▄███▄▄▄▄      ▄████████    ▄███████▄                            
          ███▀▀▀██▄ ▄██▀▀▀███▀▀▀██▄   ███    ███   ███    ███                            
          ███   ███ ███   ███   ███   ███    ███   ███    ███                            
          ███   ███ ███   ███   ███   ███    ███   ███    ███                            
          ███   ███ ███   ███   ███ ▀███████████ ▀█████████▀                             
          ███   ███ ███   ███   ███   ███    ███   ███                                   
          ███   ███ ███   ███   ███   ███    ███   ███                                   
           ▀█   █▀   ▀█   ███   █▀    ███    █▀   ▄████▀                                                                                   
''')     
    time.sleep(0.5)
    print('\033[35m'+'''
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
                            (Ferramenta criada para facilitar comandos com NMAP)
                                        (Para Opções, digite help)
''')  
    time.sleep(3.5)

def menu():
    os.system('clear')
    print ('''
                                __COMANDOS__ 

       1 = Este menu retornará todas as opções referentes  a scan de redes
           |essas funções são utilizadas para enumerar hosts conectados na rede|

       2 = Este menu retornará todas as opções referentes a reconhecimento de um host especifico
           |funções eficientes para enumerar informações especificas sobre um ou mais alvos|

       3 = Este menu retornará todas as opções referentes a exploração de vulnerabilidades em um alvo
           |estas funções servem para explorar vulnerabilidades existentes nos alvos|
       
           |É Recomendado utilizar as opções 1 e 2 antes de ir para a 3.|

       4 = Opções do menu principal 
       5 = Fecha o programa
       
      ''')

#level 1 SCANS     
def subMenuUm():
    print ('''
                                __COMANDOS_SCANS__ 

       ack = Irá executar um ACK scan no escopo
       syn = Irá executar um SYN scan no escopo
       udp = Irá executar um UDP scan no escopo
       arp = Irá executar um ARP scan no escopo
       icmp = Irá executar um ICMP scan no escopo
       sctp = Irá executar um SCTP INIT scan no escopo
       ip = Irá executar um IP scan no escopo (utiliza os seguintes protocolos para varredura: IGMP, IP-in-IP, ICMP, UDP e SCTP)
       broad = Irá executar um scan na rede usando pacote broadcast ping
       sec = Irá executar um scan no escopo em busca de WAF/IPS
      ''')

#level 2 RECONHECIMENTO
def subMenuDois():
    print ('''
                                __COMANDOS_RECONHECIMENTO__ 

       serv = Irá executar uma varredura nos serviços do escopo
       op = Irá executar uma varredura em busca do sistema operacional do escopo
       http = Irá executar uma varredura para verificar quais metodoso escopo aceita
       smb = Irá executar no escopo uma varredura enumerando vulnerabilidades no SMB 
       proxy = Irá executar no escopo uma varredura em busca de um http-proxy aberto
       direct = Irá executar no escopo uma varredura em busca de arquivos e diretórios dentro de aplicações (FUZZER)
       brute = Irá executar no escopo brute-force afim de enumerar dados (padrão, wordpress, joomla)
       xss = Irá executar no escopo uma busca por XSS (padrão, php)
       sqli = Irá executar no escopo uma busca por querys sql vulneráveis
       git = Irá executar no escopo uma busca por git EXPOSED
       shellshock = Irá verificar no escopo a presença de um shellshock exposto (CVE-2014-6271)
       ssl = Irá Auditar a força dos pacotes de criptografia em servidores SSL do escopo
      ''')   

#level 3 VULNERABILIDADES
def subMenuTres():
    print ('''
                                __COMANDOS_VULNERABILIDADES__ 

       all = Irá identificar as vulnerabilidades presentes no escopo de acordo com uma busca padrão do nmap
       smb = Irá listar compartilhamentos abertos e vulnerabilidades SMB
       default = Irá procurar por credenciais padrões em webcams, impressoras, sistemas VoIP, sistemas de videoconferência e outros aparelhos
       shellshock = se aproveitará da CVE-2014-6271 para executar comandos remotos no host
      ''')      
          
def jogo_da_velha():
    print("####################################################################################################")