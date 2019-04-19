   ##########################################################################################################
   #                                                                                                        #       
   #             Bu Python Programı Barbaros Anadolu Lisesi Adına Geliştirilmiştir                          #
   #  Yapılma Amacı Pi Sayısında Aranan Sayı Değerini Kaçıncı Basamakta İtibaren Başladığını Tespit Etmek   #
   #             Program GPL2 Lisanslıdır Ticari Amaçlar Dahil Kullanılabilir                               #
   #                                                                                                        #                           
   #                                                                                                        #
   ##########################################################################################################

import random
import re                   
import sys
import time
from progressbar import *
import threading
from tqdm import tqdm

#from progressbar import AnimatedMarker, Bar, BouncingBar, Counter, ETA, \
#    AdaptiveETA, FileTransferSpeed, FormatLabel, Percentage, \
#    ProgressBar, ReverseBar, RotatingMarker, \
#    SimpleProgress, Timer, UnknownLength

#Açıklama Satırı Kullanılmayacak

"""    
examples = []                                                     
def example(fn):
    try: name = 'Example %d' % int(fn.__name__[7:])
    except: name = fn.__name__

    def wrapped():                                              
        try:
            sys.stdout.write('Running: %s\n' % name)
            fn()
            sys.stdout.write('\n')
        except KeyboardInterrupt:
            sys.stdout.write('\nSkipping example.\n\n')

    examples.append(wrapped)
    return wrapped
"""
#Açıklama Satırı Kullanılmayacak

dosya = open("pi2.txt","r")

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
            ░                                                   """)
print(" MC-TEAM Tarafından Yapılıp Geliştirilmiştir. ")
print("")

data = dosya.read()

f = data 
h = input ("Aranacak Sayı Değerini Giriniz:")

Onay = input("İşlem Başlasınmı(E/H):")
#Açıklama Satırı 
"""
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
                
                
                

kill = False      
stop = False
p = progress_bar_loading()
p.start()

try:
     
    time.sleep(1)
    stop = True
    print ("")
except KeyboardInterrupt or EOFError:
         kill = True
         stop = True
"""
#Açıklama Satırı


pi_value = 4.0
four = 4.0
denominator_value = 3.0
iterations = 700


for i in range(0, iterations):
    if pi_value == 4: 
        pi_value = float(pi_value - float(four / denominator_value))
        print("%0.20f" % pi_value)
        denominator_value += 2

    if i % 2 == 0: 
        pi_value = float(pi_value + float(four / denominator_value))
        print("%0.20f" % pi_value)
        denominator_value = denominator_value + 2

    if i % 2 == 1: 
        pi_value = float(pi_value - float(four / denominator_value))
        print("%0.20f" % pi_value)
        denominator_value = denominator_value + 2


print("Hesaplama Tamamlandı")
print("Aranıyor...")
for x in tqdm(range(1000)):
    time.sleep(0.01)

pisayisi_uzunlugu=len(f)
aranan_uzunluk=len(h)
sayac=0
if h in f:
    #print("Aradığınız Sayı Mevcut.Şimdi yerini arıyorum...")
    print("Hesaplanan Pi Sayısının Uzunluğu",pisayisi_uzunlugu,"Aradığınız Sayının uzunluğu",aranan_uzunluk,"Basamak")
    for i in range(0,pisayisi_uzunlugu):
        if f[i]==h[0]:
            bulundu_mu=True
            if (aranan_uzunluk+i)<=pisayisi_uzunlugu:
                for c in range(0,aranan_uzunluk):
                        if f[c+i] !=h[c]:
                            bulundu_mu=False
            else:
                bulundu_mu=False
            if bulundu_mu==True:
                print("Aradığınız Sayı",i+1,".ci basamakta.." )
        # else:
        # print("Aradığınız metin, Girilen metin içinde bulunamadı")
