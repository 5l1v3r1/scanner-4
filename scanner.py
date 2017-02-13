# -*- coding: UTF-8 -*-
#!/usr/bin/env python

from __future__ import unicode_literals
import json
import sys
from operator import itemgetter
from sets import Set
import socket
import fcntl
import struct
import os
import ipaddress
import commands

import ConfigParser
Config = ConfigParser.ConfigParser()

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from pyfiglet import Figlet
f = Figlet(font="slant")

import argparse
parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

import utils

#UID CONTROL

if os.getuid() != 0:
	print utils.error("Root kullanıcısı ile çalıştırınız")
	sys.exit()

#BANNER
print f.renderText("Lostar")
print utils.error("Automated Penetration Test Toolkit v0.2\n")

#ARGUMENT PARSING
parser.add_argument("-p","--project",type=str,help="Project directory name",default="project")
parser.add_argument("-r","--report",type=str,help="Report file name",default="report.txt")
parser.add_argument("-i","--interface",type=str,help="Network interface name",required=True)
parser.add_argument("-s","--scan",type=int,help="Nessus scan id", required=True)
parser.add_argument("-t","--timeout",type=float,help="Timeout value",default=1)
args = parser.parse_args()

#CONFIG FILE
CONFIG_FILE="config"
Config.read(CONFIG_FILE)

#NESSUS CONFIG
ACCESS_KEY = Config.get("NessusConfig","accessKey")
SECRET_KEY = Config.get("NessusConfig","secretKey")
BASE_URL = Config.get("NessusConfig","url")
HEADERS = "accessKey=%s; secretKey=%s;" %(ACCESS_KEY,SECRET_KEY)
REQUEST_HEADER = {"X-ApiKeys":HEADERS}
SCAN_ID = args.scan

#FILE CONFIG
PROJECT_NAME = args.project
REPORT_FILENAME = args.report
RANGE_FILENAME = "range.txt"
IS_RANGE_VALID = False
SOURCE_PATH = os.getcwd()
PROJECT_PATH = SOURCE_PATH + utils.slash + PROJECT_NAME
REPORT_PATH = PROJECT_PATH + utils.slash + REPORT_FILENAME
RANGE_PATH = PROJECT_PATH + utils.slash + RANGE_FILENAME

#NETWORK CONFIG
INTERFACE =  args.interface
TIMEOUT = args.timeout
RANGE_LIST = []

#RANGE VALIDATION
def isValid(string):
	if string.__contains__(utils.slash):
		ip = string.split(utils.slash)[0]
		prefix = string.split(utils.slash)[1]

		try:
			if int(prefix) > 32 or int(prefix)< 0:
				return False
		except Exception as e:
			return False

		return isIpValid(ip)

	else:
		return isIpValid(string)

def isIpValid(ip):
	octets = ip.split(".")
	if len(octets) != 4:
		return False

	for i in octets:
		try:
			if int(i) > 255 or int(i) < 0:
				return False
		except Exception as e:
			return False

	return True

def checkIpValid():
	range_file = open(PROJECT_PATH + utils.slash + RANGE_FILENAME,"r")
	for line in range_file:
		line = line.replace(utils.newline,"")
		if line != "":
			valid = isValid(line)
			if not valid:
				return False
	range_file.close()
	return True

#DIRECTORY CONTROL
def checkDirExists():
	dirs = os.listdir(".")
	for i in dirs:
		if i == PROJECT_NAME:
			return True
	return False

def createFiles():
	if checkDirExists():
		print utils.error("Aynı proje dosyası zaten var.Devam ederseniz eski dosya silinecek.")
		while True:
			answer = raw_input(utils.question("Devam edilsin mi? Y/N "))
			if answer=="Y" or answer =="y" or answer=="":
				os.system("rm -rf " + PROJECT_NAME)
				os.system("mkdir " + PROJECT_NAME)
				os.system("touch " + REPORT_PATH)
				os.system("touch " + RANGE_PATH)
				print utils.success("Yeni proje dosyası oluşturuldu.")
				break
			elif answer=="N" or answer == "n":
				print utils.info("Çıkış yapılıyor.")
				sys.exit()
	else:
		os.system("mkdir " + PROJECT_NAME)
		os.system("touch " + REPORT_PATH)
		os.system("touch " + RANGE_PATH)		

def checkPentesterIp():
	global INTERFACE
	report_file = open(REPORT_PATH,"a")
	report_file.write("PENTESTER IP"+utils.newline)
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ip =  str(socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s',str(INTERFACE)[:15]))[20:24]))
		report_file.write(ip+utils.newline)
		report_file.write(utils.newline)
	except Exception as e:
		print utils.error("Pentester Ip adresi nota eklenemedi.")
		raise
	finally:
		report_file.close()
		print utils.success("Pentester Ip adresi nota eklendi.")

def checkTestRange():
	global IS_RANGE_VALID
	print utils.info("Test kapsamını " + RANGE_FILENAME + " dosyasına ekleyiniz.")
	os.system("gedit " + PROJECT_PATH + utils.slash + RANGE_FILENAME + " > /dev/null 2>&1")
	while True:
		answer = raw_input(utils.question("Test kapsamı dosyaya eklendi mi ? Y/N "))
		if answer=="Y" or answer =="y" or answer=="":
			print utils.info("Kapsam kontrol ediliyor")
			valid = checkIpValid()
			if valid:
				report_file = open(REPORT_PATH,"a")
				range_file = open(RANGE_PATH,"r")
				
				report_file.write("TEST KAPSAMI" + utils.newline)

				for line in range_file:
					report_file.write(line)

				report_file.write(utils.newline)
				report_file.close()
				range_file.close()

				print utils.success("Test kapsamı başarıyla nota eklendi.")
				IS_RANGE_VALID = True
			else:
				print utils.error("Test kapsamını doğru değil.")
				print utils.info("Çıkış yapılıyor.")
				sys.exit()
			break
		elif answer=="N" or answer == "n":
			print utils.error("Test kapsamını nota eklenmedi. Bazı fonksiyonlar kullanılamayacak.")
			IS_RANGE_VALID = False
			break

def checkArpPoisoning():
	report_file = open(REPORT_PATH,"a")
	report_file.write("ARP POISONING" + utils.newline)
	report_file.write(utils.newline)
	report_file.close()
	while True:
		answer = raw_input(utils.question("Arp Poisoning kontrol edildi mi? Y/N "))
		if answer=="Y" or answer =="y" or answer=="":
			report_file = open(REPORT_PATH,"a")
			print utils.success("Bulguları nota ekleyiniz.")
			break
		elif answer=="N" or answer == "n":
			print utils.info("Arp Poisoning kontrolü yapınız")
			os.system("ettercap -G > /dev/null 2>&1")
			break

def checkLlmnrPoisoning():
	report_file = open(REPORT_PATH,"a")
	report_file.write("LLMNR POISONING" + utils.newline)
	report_file.write(utils.newline)
	report_file.close()
	while True:
		answer = raw_input(utils.question("Llmnr Poisoning kontrol edildi mi? Y/N "))
		if answer=="Y" or answer =="y" or answer=="":
			print utils.success("Bulguları nota ekleyiniz.")
			break
		elif answer=="N" or answer == "n":
			print utils.info("Llmnr Poisoning kontrolü yapınız")
			command = "sudo responder -I " + INTERFACE
			os.system(command)
			break

def checkDnsTunneling():
	report_file = open(REPORT_PATH,"a")
	report_file.write("DNS TUNNELING" + utils.newline)
	report_file.write(utils.newline)
	report_file.close()
	while True:
		answer = raw_input(utils.question("DNS Tunneling kontrol edildi mi? Y/N "))
		if answer=="Y" or answer =="y" or answer=="":
			print utils.success("Bulguları nota ekleyiniz.")
			break
		elif answer=="N" or answer == "n":
			print utils.info("DNS Tunnel kontrolü yapınız")
			#starting iodine
			break

def checkReverseShell():
	report_file = open(REPORT_PATH,"a")
	report_file.write("REVERSE SHELL" + utils.newline)
	report_file.write(utils.newline)
	report_file.close()
	while True:
		answer = raw_input(utils.question("Reverse Shell kontrol edildi mi? Y/N "))
		if answer=="Y" or answer =="y" or answer=="":
			print utils.success("Bulguları nota ekleyiniz.")
			break
		elif answer=="N" or answer == "n":
			print utils.info("Reverse Shell kontrolü yapınız")
			break

def controlFileSharing():
	if not IS_RANGE_VALID:
		print utils.error("File Sharing kontrol edilemiyor.")
		return False

	report_file = open(REPORT_PATH,"a")
	range_file = open(RANGE_PATH,"r")

	for line in range_file:
		ip = line.replace(utils.newline,"")
		if ip != "":
			if ip.__contains__("/"):
				for i in ipaddress.ip_network(ip).hosts():
					result = fileSharing(str(i.exploded))
					if result['sharing']:
						report_file.write(ip + utils.newline)
						for d in result['dirs']:
							report_file.write(d + utils.newline)

					if not result['sharing'] and result['info']:
						report_file.write(ip + utils.newline)
						report_file.write("Domain" + utils.semicolon + utils.space + result['domain'] + utils.newline)
						report_file.write("OS" + utils.semicolon + utils.space + result['os'] + utils.newline)
						report_file.write("SERVER" + utils.semicolon + utils.space + result['server'] + utils.newline)
					report_file.write(utils.newline)
			else:		
				result = fileSharing(ip)
				if result['sharing']:
					report_file.write(ip + utils.newline)
					for d in result['dirs']:
						report_file.write(d + comma)
					report_file.write(utils.newline)

				if result['info']:
					if not result['sharing']:
						report_file.write(ip + utils.newline)
					report_file.write("Domain" + utils.semicolon + utils.space + result['domain'] + utils.newline)
					report_file.write("OS" + utils.semicolon + utils.space + result['os'] + utils.newline)
					report_file.write("SERVER" + utils.semicolon + utils.space + result['server'] + utils.newline)
				report_file.write(utils.newline)

	range_file.close()
	report_file.close()
	print utils.success("File Sharing başarıyla rapora eklendi")

def checkFileSharing():
	report_file = open(REPORT_PATH,"a")
	report_file.write("FILE SHARING" + utils.newline)
	report_file.write(utils.newline)
	report_file.close()
	while True:
		answer = raw_input(utils.question("File sharing kontrol edildi mi? Y/N "))
		if answer=="Y" or answer =="y" or answer=="":
			print utils.success("Bulguları nota ekleyiniz.")
			break
		elif answer=="N" or answer == "n":
			print utils.info("File Sharing kontrolü yapılıyor")
			controlFileSharing()
			break

class vulnerability:
	def __init__(self):
		self.port = ""
		self.ips = Set()
		self.metasploit_name = None

class prt:
	def __init__(self,port):
		self.port = port
		self.ips = Set()

class sv:
	def __init__(self,service_type):
		self.service_type = service_type
		self.ports = []

	def getSize(self):
		return len(self.ports)

def getMetasploitName(plugin_info):
	try:
		metasploit_name = plugin_info['plugindescription']['pluginattributes']['vuln_information']['exploit_frameworks']['exploit_framework'][0]['exploits']['exploit'][0]['name']
	except Exception as e:
		metasploit_name = None
	return metasploit_name

def getApiData(API_PATH):
	PLUGIN_URL = BASE_URL + utils.slash + API_PATH
	response = requests.api.request('get', PLUGIN_URL, headers=REQUEST_HEADER, verify=False)
	data = json.loads(response.text)
	return data


def add(arr,sv):
	port = sv.port
	if search(arr,port):
		arr.append(sv)
	else:
		for i in arr:
			if i.port == port:
				for host in sv.ips:
					i.ips.add(host)
	return arr

def search(arr,port):
	for i in arr:
		if i.port == port:
			return False
	return True



def getPluginDetails(plugin_id):
	API_PATH = "scans" + utils.slash + str(SCAN_ID) + utils.slash + "plugins" + utils.slash + str(plugin_id)
	data = getApiData(API_PATH)
	plugin_details = data['outputs']
	plugin_info = data['info']

	info = []

	metasploit_name = getMetasploitName(plugin_info)

	for plugin_detail in plugin_details:
		
		for port in plugin_detail['ports']:
			vuln = vulnerability()
			vuln.port = port.split()[0]
			for host in plugin_detail['ports'][port]:
				vuln.ips.add(host['hostname'])
				print host['hostname']
			
			info = add(info,vuln)
	
	for i in info:
		print i.port
		print i.ips

	return [info,metasploit_name]

def checkVulnerabilities():
	print utils.info("Zafiyetler rapora ekleniyor")
	API_PATH = "scans" + utils.slash + str(SCAN_ID)
	data = getApiData(API_PATH)
	vulnerabilities = data['vulnerabilities']
	vulnerabilities = sorted(vulnerabilities,key=itemgetter('plugin_name'))

	report_file = open(REPORT_PATH,"a")

	for vuln in vulnerabilities:
		if vuln['severity'] > 1:
			plugin_name = vuln["plugin_name"]
			plugin_id = vuln["plugin_id"]
			print plugin_name
			[plugin_details,metasploit_name] = getPluginDetails(plugin_id)
			report_file.write(plugin_name + utils.newline)
			if metasploit_name != None:
				report_file.write("MSF Name: " + metasploit_name + utils.newline)
			
			for plugin_detail in plugin_details:
				if int(plugin_detail.port.split()[0]) != 0:
					report_file.write(utils.tab + "Port " + plugin_detail.port.split()[0] + utils.newline)
				for ip in plugin_detail.ips:
					report_file.write(utils.tab + ip + utils.newline)
				
				report_file.write(utils.newline)

	report_file.close()
	print utils.success("Zafiyetler başarıyla rapora eklendi")

def checkWebConnection(host,port):
	url = "http" + utils.semicolon + 2*utils.slash + host + utils.semicolon + str(port)
	try:
		response = requests.get(url,timeout=TIMEOUT,allow_redirects=True)
		content = response.content 
		status_code = response.status_code
		if status_code != 403 and status_code != 404 and status_code != 500 and status_code != 400:
			return True
		else:
			return False
	except Exception as e:
		return False

def checkServiceConnections(services):
	
	report_file = open(REPORT_PATH,"a")

	temp_services = sv(utils.WEB_PORT)

	if services.service_type == utils.WEB_PORT:
		
		for service in services.ports:
			
			port = service.port
			temp_port = prt(port)
			temp_port.ips = set(service.ips)
			
			for ip in service.ips:
				if not checkWebConnection(ip,port):
					temp_port.ips.remove(ip)
			
			temp_services.ports.append(temp_port)
		
		report_file.write("HTTP Servisleri" + utils.newline)
		counter = 0
		for service in temp_services.ports:
			port = service.port
			if len(service.ips) > 0:
				report_file.write(utils.tab + "Port" + utils.space + str(port) + utils.newline)
				for ip in service.ips:
					counter += 1
					url = "http" + utils.semicolon + 2*utils.slash + ip + utils.semicolon + str(port)
					report_file.write(utils.tab + url + utils.newline)

		report_file.write(utils.newline)
	
	elif services.service_type == utils.SMTP_PORT:
		
		report_file.write("SMTP Servisleri" + utils.newline)		
		for service in services.ports:
			port = service.port
			report_file.write(utils.tab + "Port" + utils.space + str(port) + utils.newline)
			for ip in service.ips:
				report_file.write(utils.tab + ip + utils.semicolon + str(port) + utils.newline)
			
		report_file.write(utils.newline)

	elif services.service_type == utils.TELNET_PORT:
		
		report_file.write("TELNET Servisleri" + utils.newline)
		
		for service in services.ports:
			port = service.port
			report_file.write(utils.tab + "Port" + utils.space + str(port) + utils.newline)
			for ip in service.ips:
				report_file.write(ip + utils.semicolon + str(port) + utils.newline)
		
		report_file.write(utils.newline)

	elif services.service_type == utils.FTP_PORT:
		
		report_file.write("FTP Servisleri" + utils.newline)
		
		for service in services.ports:
			port = service.port
			report_file.write(utils.tab + "Port" + utils.space + str(port) + utils.newline)
			for ip in service.ips:
				report_file.write(utils.tab + ip + utils.semicolon + str(port) + utils.newline)

		report_file.write(utils.newline)

	report_file.close()

def checkServices():
	print utils.info("Servisler kontrol ediliyor")
	API_PATH = "scans" + utils.slash + str(SCAN_ID) + utils.slash + "plugins" + utils.slash + "22964"
	data = getApiData(API_PATH)
	services = data['outputs']
	
	www = sv(utils.WEB_PORT)
	telnet = sv(utils.TELNET_PORT)
	smtp = sv(utils.SMTP_PORT)
	ftp = sv(utils.FTP_PORT)

	for service in services:
		ports = service['ports'].keys()
		for port in ports:
			service_type = port.split()[len(port.split())-1]
			port_num = port.split()[0]
			p = prt(int(port_num))
			
			if service_type == utils.WEB_PORT:
				for host in service['ports'][port]:
					p.ips.add(host['hostname'])
				www.ports.append(p)
			elif service_type == utils.SMTP_PORT:
				for host in service['ports'][port]:
					p.ips.add(host['hostname'])
				smtp.ports.append(p)
			elif service_type == utils.FTP_PORT:
				for host in service['ports'][port]:
					p.ips.add(host['hostname'])
				ftp.ports.append(p)
			elif service_type == utils.TELNET_PORT:
				for host in service['ports'][port]:
					p.ips.add(host['hostname'])
				telnet.ports.append(p)

	if www.getSize() > 0:
		checkServiceConnections(www)
	if telnet.getSize() > 0:
		checkServiceConnections(telnet)
	if smtp.getSize() > 0:
		checkServiceConnections(smtp)
	if ftp.getSize() > 0:
		checkServiceConnections(ftp)
	
	print utils.success("Servisler başarıyla rapora eklendi")

def fileSharing(ip):
	result = {
		"sharing" : False,
		"info" : False,
		"domain" : None,
		"os" : None,
		"server" : None,
		"dirs" : []
	}

	output = commands.getoutput("smbclient -L " + ip +" -N -g -t" + utils.space + str(TIMEOUT))
	lines = output.splitlines()

	if lines[0].__contains__("Error") or lines[0].__contains__("failed"):
		return result
	elif lines[0].__contains__("Domain"):
		result['info'] = True
		info = lines[0].split("=")
		result['domain'] = info[1].split()[0].replace("[","").replace("]","")
		result['os'] = info[2].split("]")[0].replace("[","").replace("]","")
		result['server'] = info[3].replace("[","").replace("]","")

	if utils.decode(lines[2]).__contains__("Error"):
		return result
	elif utils.decode(lines[2]).__contains__("|"):
		result['sharing'] = True
		for line in lines:
			if utils.decode(line).__contains__("|"):
				dir_info = decode(line).split("|")
				result['dirs'].append(dir_info[1])
		return result

def main():
	createFiles()
	checkPentesterIp()
	checkTestRange()
	checkArpPoisoning()
	checkLlmnrPoisoning()
	checkDnsTunneling()
	checkReverseShell()
	checkFileSharing()
	checkVulnerabilities()
	checkServices()

main()
