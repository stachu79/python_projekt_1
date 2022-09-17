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

    #file = open("/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt", errors='ignore')
    #if file:
    #    directory = file.read().split("\n")
