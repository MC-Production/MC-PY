import  re
import time
import sys
from progressbar import *
import threading 

dosya = open("pi2.txt","r")

print(" ███╗   ███╗ ██████╗              ████████╗███████╗ █████╗ ███╗   ███╗ ")
print(" ████╗ ████║██╔════╝              ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║ ")
print(" ██╔████╔██║██║         █████╗       ██║   █████╗  ███████║██╔████╔██║ ")
print(" ██║╚██╔╝██║██║         ╚════╝       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║ ")
print(" ██║ ╚═╝ ██║╚██████╗                 ██║   ███████╗██║  ██║██║ ╚═╝ ██║ ")
print(" ╚═╝     ╚═╝ ╚═════╝                 ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ")
print("MC-TEAM Tarafından Yapılıp Geliştirilmiştir (M = Muhammet C = ? )      ")
print("")

onay = input("Testler Başlasınmı(E/H):")
               
class progress_bar_loading(threading.Thread):

    def run(self):
            global stop
            global kill
            print ('Yükleniyor....  '),
            sys.stdout.flush()
            i = 1000000
            while stop != True:
                    if (i%4) == 0: 
                        sys.stdout.write('\b/')
                    elif (i%4) == 1: 
                        sys.stdout.write('\b-')
                    elif (i%4) == 2: 
                        sys.stdout.write('\b\\')
                    elif (i%4) == 3: 
                        sys.stdout.write('\b|')
                    if (i%4) == 0: 
                        sys.stdout.write('\b/')
                    elif (i%4) == 1: 
                        sys.stdout.write('\b-')
                    elif (i%4) == 2: 
                        sys.stdout.write('\b\\')
                    elif (i%4) == 3: 
                        sys.stdout.write('\b|')
                    
                    
                    sys.stdout.flush()
                    time.sleep(0.2)
                    i+=1

            if kill == True: 
                print ('\b\b\b\b ABORT!'),
            else:
                print ("")
                
                

kill = False      
stop = False
p = progress_bar_loading()
p.start()

try:
    #anything you want to run. 
    time.sleep(1)
    stop = True
    print ("\nTestler Tamamlandı")
except KeyboardInterrupt or EOFError:
         kill = True
         stop = True
         

Pi = input("\nPi.py Çalıştırılsınmı(E/H):")

Aranansayi = input("Aranacak Sayıyı giriniz:")
data = dosya.read()

for i in range(len(data)):
    b = re.search(Aranansayi,data)
    if b:
        yeni_dosya=open("Arama_Sonucu.txt","w")
        yeni_dosya.write(b.group())
        break

    else:
        print("Aranılan Değer bulunamadı.")
        break
