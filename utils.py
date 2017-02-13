from blessings import Terminal
term = Terminal()

#CHARS
tab = "\t"
dquote = "\""
newline = "\n"
slash = "/"
space = " "
semicolon = ":"
comma = ","

#KEYWORDS FOR SERVICES
WEB_PORT = "www"
TELNET_PORT = "telnet"
SMTP_PORT = "smtp"
FTP_PORT = "ftp"

#UTF-8 CHAR DECODE
def decode(string):
	return string.decode("utf-8")

def encode(string):
	return string.encode("utf-8")

#NOTIFICATION CONFIG
def question(string):
	return encode(term.bold_blue("[?] " + string))

def error(string):
	return encode(term.bold_red("[*] " + string))

def success(string):
	return encode(term.bold_green("[+] " + string))

def info(string):
	return encode(term.bold_yellow("[!] " + string))

def up(string,lineFeed):
	return term.move_up() * lineFeed + string