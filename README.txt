AnyOTPManager 1.0
=================

Bağımsız Windows masaüstü uygulaması. KnightVision kurulumu, oyun, USB cihazı
veya internet bağlantısı gerekmez. Arayüz Türkçedir.

BAŞLATMA
GitHub'dan kaynak kodu aldıysanız Windows'ta .NET 10 SDK kurulu olmalıdır.
Proje klasöründe çalıştırın:
  powershell -ExecutionPolicy Bypass -File tools/Publish.ps1
Bu komut uygulamayı ve kısayolu oluşturur.

Proje klasöründeki AnyOTPManager.lnk kısayolunu veya app\AnyOTPManager.exe
dosyasını açın. app sürümü Windows x64 için kendi .NET çalışma zamanını içerir.

BU BİLGİSAYARDAN KAYIT EKLEME
1. Sol menüde "Dosyadan ekle"nin üstündeki "Bu bilgisayardan ekle"ye basın.
2. Kayıt adını yazın. Diskler otomatik listelenir; AnyOTP'nin kullandığı diski seçin.
3. Bu bilgisayardaki AnyOTP kaydının mevcut 6 rakamlı PIN'ini girin.
4. "Kaydı ekle"ye basın. PIN ve cihaz eşleşmesi doğrulanınca kayıt listeye eklenir.

TXT veya REG dosyası gerekmez. Kaynak, mevcut Windows kullanıcısının 32 bit
HKCU\Software\AnyOTP kaydıdır; kaynak kayıt değiştirilmeden korumalı kasaya
bir kopyası alınır. AnyOTP uygulamasını kapatmak gerekmez. Bu Windows hesabında
kayıt yoksa bilgi mesajı gösterilir; dosyadan ekleme seçeneği kullanılabilir.
Yanlış PIN/disk, eksik kayıt ve aynı OTP'nin tekrar eklenmesi reddedilir.

DOSYADAN KAYIT EKLEME
1. "Kayıt ekle"ye basın ve bir alias yazın.
2. Aynı AnyOTP yedeğine ait TXT ve REG dosyalarını seçin.
   TXT: kaynak disk PNP kimliği, ondalık disk imzası, isteğe bağlı eski bayrak.
   REG: HKCU\Software\AnyOTP kaydı; VMData ve EnvInfo gereklidir.
3. Dosyaların doğru, mevcut PIN'ini girin. Formun varsayılanı 290785'tir.
   Kaynak PIN farklıysa bu alana o PIN yazılmalıdır.
4. PIN, kayıt bütünlüğü ve dosya eşleşmesi doğrulanınca kayıt listeye eklenir.
   Orijinal TXT ve REG dosyaları değiştirilmez.

Birden fazla kayıt saklanır. Alias altında güncel kod ve yenilenme süresi
görünür. Günlük kullanımda ve yeniden açılışta tekrar PIN sorulmaz.
Arama, ad düzenleme ve listeden kaldırma desteklenir. Aynı seed veya aynı
alias ikinci kez eklenmez. "Kodu kopyala" güncel zamanın kodunu alır.
Pano, hâlâ uygulamanın kopyaladığı kodu içeriyorsa 20 saniye sonra temizlenir.

PIN DEĞİŞTİRME
Seçilen kayıtta "PIN değiştir"e basın. Yeni PIN alanları varsayılan olarak
290785 ile gelir; istenen 6 rakam girilebilir. Aynı OTP anahtarı yeni PIN ile
yeniden şifrelenir. Kod dizisi ve zaman parametreleri korunur.
Bu işlem yöneticideki kaydı günceller. Orijinal dosyaları veya Windows'ta
etkin AnyOTP kaydını değiştirmez. Güncel TXT + REG çifti "TXT + REG dışa aktar"
ile alınabilir; etkin kayıt "Bu bilgisayara aktar" ile güncellenebilir.

BU BİLGİSAYARA AKTAR
Önce AnyOTP uygulamasını kapatın. Kayıt seçip "Bu bilgisayara aktar"e basın.
Yerel diski seçin; PNPDeviceID ve Signature otomatik okunur. SerialNumber
kullanılmaz. Varsayılan aktarım PIN'i 290785'tir.
Aktarım, aynı seed ve EnvInfo'yu hedef disk ve seçilen PIN ile yeniden
şifreleyip mevcut Windows kullanıcısının 32 bit AnyOTP kaydına yazar.
AnyOTP'de tek kayıt etkin olabilir; yönetici içinde çoklu kayıtlar korunur.
Önce mevcut kayıt korumalı olarak yedeklenir, yazma sonrasında tekrar okunur.
"Aktarımı geri al" önceki kaydı doğrulayarak geri yükler. Harici bir uygulama
kaydı sonradan değiştirmişse üzerine otomatik yazılmaz.
Yarım kalmış aktarım varsa yeni aktarım engellenir ve geri alma gösterilir.

VERİLER
%LOCALAPPDATA%\AnyOTPManager\profiles.dpapi
%LOCALAPPDATA%\AnyOTPManager\profiles.dpapi.previous
%LOCALAPPDATA%\AnyOTPManager\backups\

Seed, PIN, alias ve profil bilgileri birlikte Windows CurrentUser DPAPI ile
korunur. "PIN sormadan" kullanım, diske düz metin seed yazılması anlamına gelmez.
Kayıtlar bu Windows hesabına bağlıdır. Başka bilgisayara taşımak için seçilen
kaydın TXT + REG dosyalarını dışa aktarın ve orada mevcut PIN ile içe aktarın.
Kaynak klasörünü veya uygulama dosyalarını taşımak kullanıcı verilerini silmez.
Listeden kaldırma, orijinal yedekleri veya etkin AnyOTP kaydını silmez.
Bozuk / bilinmeyen sürümlü kasa otomatik sıfırlanmaz.

KAPSAM
İncelenen AnyOTP PC 1.18.0.78 kayıt biçimi: 20 bayt seed, 4 bayt big-endian
sayaçlı HMAC-SHA1, sabit epoch 946652400, EnvInfo'ya göre 15/30/60 saniye,
6/7/8 hane. Standart TOTP veya Android yedeği içe aktarma özelliği yoktur.
EnvInfo hane alanındaki sıfır veya boşluk dolgusu (örneğin "06", "6 ", " 6")
desteklenir; doğrulamada ve dışa aktarmada özgün EnvInfo baytları korunur.
Bilgisayarın tarih/saatinin doğru olması gerekir.
Sunucuya hesap kaydı, oturum açma, klavye girdisi veya hesap doğrulaması yapılmaz.

GELİŞTİRME
.NET 10 SDK ve Windows gereklidir.
  dotnet build AnyOTPManager.slnx -c Release
  dotnet test AnyOTPManager.slnx -c Release --no-build
  dotnet run --project tools/AnyOTPManager.NativeCheck -c Release -- vendor/anyotp artifacts/native-verification.json
  dotnet run --project tools/AnyOTPManager.UiCheck -c Release -- artifacts/ui
  powershell -ExecutionPolicy Bypass -File tools/Publish.ps1

src\AnyOTPManager.Core: kayıt dosyası okuma/yazma ve OTP kriptografisi.
src\AnyOTPManager.Windows: korumalı kasa, disk okuma, tek yazarlı yönetici,
  aktarım / yedek / geri alma. WPF işlem otoritesi değildir.
src\AnyOTPManager.App: WPF görünüm ve komutlar.
tests: gerçek Core / Windows derlemelerine bağlı sentetik kabul testleri.
tools: x86 üretici karşılaştırması ve gerçek WPF ekran kabulü.
vendor\anyotp: mevcut araştırmadaki üretici DLL'lerinin hash ile sabitlenmiş
  kopyaları repoya dahildir; yalnız x86 karşılaştırma aracında kullanılır.
  Normal uygulama bu DLL'leri yüklemez ve COM kaydı yapmaz.
  Dosya listesi ve SHA256 değerleri: vendor\anyotp\README.txt.

Repoda gerçek veya test hesaplarına ait TXT/REG/DPAPI dosyaları bulunmaz.
Otomatik testler, kod içinde üretilen hayali seed ve cihaz bilgilerini kullanır;
bu fixture'lar herhangi bir hizmette kayıtlı hesaba bağlı değildir.
Derlenmiş uygulama, yerel kısayol ve test çıktıları Git'e dahil değildir.

KAYNAK VE DOĞRULAMA
ProfileFiles.cs, KnightVision.Otp/OtpProfileParser.cs üzerinden bağımsız
kopya olarak uyarlanmıştır. Projeler arasında kaynak veya derleme bağı yoktur.
Kripto sözleşmesi mevcut native disassembly'den ve bu projede yeniden yapılan
üretici DLL karşılaştırmasından gelir. Bulgular / kesin komutlar:
docs\VERIFICATION.txt

Platform başvuruları:
https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata
https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registryview
https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-diskdrive
