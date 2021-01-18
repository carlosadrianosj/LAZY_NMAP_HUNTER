# LAZY_NMAP_HUNTER
Este projeto tem como intuito facilitar a utilização do NMAP com um sistema mais interativo para o usuário via terminal.

O NMAP é uma ferramenta completa, com inúmeras funcionalidades, entretanto requer que o usuário tenha certa maestria com
ele para que extraia 100% de sua capacidade, o Lazy_NMAP_Hunter vem então para facilitar essa interação. Em sua atual versão 
a ferramenta possui as seguintes opções:

       
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
       
       
                                       __COMANDOS_VULNERABILIDADES__ 

       all = Irá identificar as vulnerabilidades presentes no escopo de acordo com uma busca padrão do nmap
       smb = Irá listar compartilhamentos abertos e vulnerabilidades SMB
       default = Irá procurar por credenciais padrões em webcams, impressoras, sistemas VoIP, sistemas de videoconferência e outros aparelhos
       shellshock = se aproveitará da CVE-2014-6271 para executar comandos remotos no host
       

* Para instalar o NMAP: apt install nmap
* Para instalar o NMAP no Python: apt install python-nmap
* Para executar o programa: sudo python3 lazy_nmap_hunter.py

    
