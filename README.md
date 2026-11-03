# SentinelLog — Bulut Sunum Sürümü

Python ve Streamlit ile Mini SIEM. Güncel yerel projenin bulut sunum kopyasıdır.

## Yayınlama
1. GitHub üzerinde `sentinellog` adlı yeni repository oluşturun.
2. Bu klasörün içindeki dosyaları repository köküne yükleyin. ZIP dosyasını yüklemeyin.
3. https://share.streamlit.io üzerinde GitHub hesabıyla giriş yapın.
4. Create app: repository `sentinellog`, branch `main`, main file `app.py`.
5. Advanced settings: Python 3.11 veya 3.12. Müsait bir uygulama alt adı seçip Deploy.

## Sunum
Veri Kaynakları → Sentetik Örnek Logları Yükle. Bu kayıtlar **sentetiktir**.
Varsayılan eşik 5 ve pencere 5 dakika ile üç kural da görülebilir.
Gerçek Windows EVTX (4624/4625) veya SSH log dosyaları da yüklenebilir.
Alarm Merkezi → inceleme durumu, önem ve not kaydedin. Raporlar → CSV.

## Sınırlar
- Yerel Windows canlı toplayıcısı ve monitor.py buluta bağlı değildir.
- Performans sayfası bu durumu açıkça gösterir; sahte ölçüm üretmez.
- Her tarayıcı oturumu ayrı geçici SQLite kullanır. Notlar ve yüklemeler
  oturum içinde korunur; sayfayı tamamen yenileme, bağlantı kopması veya
  sunucu yeniden başlatılmasında kalıcılık garanti edilmez.
- Kullanıcı girişi ve merkezi kalıcı veri deposu bu sürümde yoktur.
- Yerel çalışan projenizin dosyalarının üzerine bu paketi kopyalamayın.
- Kişisel loglar, veritabanı, kimlik bilgileri ve eski kod yedekleri pakete dahil değildir.

## Yerel deneme (ayrı klasörde)
`python -m pip install -r requirements.txt`

`python -m streamlit run app.py`
