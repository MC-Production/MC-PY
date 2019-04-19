import re

f= input("Aranacak Sayıyı Giriniz:")
dosya = open("pi.txt,""r")
data = dosya.read()

for i in range(len(data)):
    b = re.search(f,data)

metin_uzunlugu=len(f)
aranan_uzunluk=len(h)
sayac=0

if f in dosya:
 print("Aradığınız Sayı Mevcut. Şimdi yerini arıyorum...")
 print("Sayının Uzunluğu",metin_uzunlugu,"",aranan_uzunluk,"karakter")

for i in range(0,metin_uzunlugu):
 if f[ i ]==h[0]:
bulundu_mu=True:

 if (aranan_uzunluk+i)<=metin_uzunlugu:

for c in range(0,aranan_uzunluk):

 if f[c+i]!=h[c]:

bulundu_mu=False

else:

bulundu_mu=False

if bulundu_mu==True:

print("Aradığınız Sayı",i+1,".ci basamaktan itibaren başlıyor..")

else:

print("Aradığını sayı, pi sayısının 2m basamağının içinde bulunamadı")
