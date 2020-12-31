# LAZY_NMAP_HUNTER
Este projeto tem como intuito facilitar a utilização do NMAP com um sistema mais interativo para o usuário via terminal.

O NMAP é uma ferramenta completa, com inúmeras funcionalidades, entretanto requer que o usuário tenha certa maestria com
ele para que extraia 100% de sua capacidade, o Lazy_NMAP_Hunter vem então para facilitar essa interação. Em sua atual versão 
a ferramenta possui as seguintes opções:

       
                                                          __COMANDOS__                                                              
    help = mostra as opções de comandos                                                                                             
    ack = irá executar um ACK scan no escopo                                                                                        
    syn = irá executar um SYN scan no escopo                                                                                        
    udp = irá executar um UDP scan no escopo                                                                                        
    arp = irá executar um ARP scan no escopo                                                                                        
    icmp = irá executar um ICMP scan no escopo                                                                                      
    sctp = irá executar um SCTP INIT scan no escopo                                                                                 
    ip = irá executar um IP scan no escopo (utiliza os seguintes protocolos para varredura: IGMP, IP-in-IP, ICMP, UDP e SCTP)       
    serv = irá executar uma varredura nos serviços do escopo                                                                        
    op = irá executar uma varredura em busca do sistema operacional do escopo                                                       
    http = irá executar uma varredura para verificar quais metodoso escopo aceita                                                   
    vuln = irá executar uma varredura em busca de vulnerabilidades no escopo (esta opção executa todos os scripts da categoria vuln)
    smb = irá executar uma varredura completa identificando e enumerando vulnerabilidades no SMB                                    
    exit = fecha o programa

* Para instalar o NMAP: apt install nmap
* Para instalar o NMAP no Python: apt install python-nmap
* Para executar o programa: sudo python3 lazy_nmap_hunter.py

    
