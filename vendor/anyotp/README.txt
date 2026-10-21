AnyOTP üretici DLL'leri
======================

Bu üç x86 DLL yalnız tools/AnyOTPManager.NativeCheck karşılaştırma aracı
tarafından kullanılır. Normal uygulama managed kripto kullanır ve bu DLL'lere
çalışma zamanı bağımlılığı yoktur. Dosyalar OTP hesabı veya profil içermez.

Karşılaştırma aracı yüklemeden önce SHA256 değerlerini doğrular:

AnyOTPBiz.dll
1DF04522A294EA58D8088A6441C2655E47BD407915D6D2E1B813B5235FC9281C

AnyOtpDLL.dll
EBC418257CE9112ED2B717D672B43FF9B74CDB107456F6658DF3FBAEF4EA5E3E

AnyOtpDLLwDH.dll
DB8B864C9F8C25C99F1FAC22803C69EE5DF04FC033625CBB871E9E055F4ACEE7

Proje kökünden çalıştırın:
  dotnet run --project tools/AnyOTPManager.NativeCheck -c Release -- vendor/anyotp artifacts/native-verification.json

Araç ayrı bir x86 süreçte sentetik profiller ve geçici, izole HKCU alanı
kullanır. Gerçek AnyOTP hesabına kayıt veya sunucuya bağlantı yapmaz.
