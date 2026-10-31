# Server SlowDNS

[Bahasa Indonesia](#bahasa-indonesia) | [English](#english)

## Bahasa Indonesia

### 1. Siapkan VPS dan Berkas

Gunakan VPS Linux dengan systemd. Siapkan domain SlowDNS yang mengarah ke VPS
dan izinkan UDP port `53` pada firewall VPS serta panel penyedia server.
Untuk memakai IPv4 dan IPv6, izinkan port tersebut pada keduanya.
Pastikan port tersebut belum digunakan layanan lain.

Masuk ke VPS sebagai root, lalu buat folder pemasangan:

```sh
mkdir -p /root/slowdns
```

Ekstrak berkas unduhan di komputer, lalu unggah `install.sh` dan `slowdns`
ke folder tersebut:

```text
/root/slowdns/
  install.sh
  slowdns
```

### 2. Jalankan Installer

```sh
bash /root/slowdns/install.sh
```

Pilih **1. Install**, lalu isi pengaturan berikut. Tekan Enter untuk memakai
nilai yang ditampilkan dalam kurung siku.

| Pengaturan | Isi dengan |
| --- | --- |
| Listener IP | Tekan Enter untuk `auto`: IPv4 dan IPv6 yang tersedia. Isi satu IP VPS jika ingin memakai alamat itu saja. |
| UDP port | `53`. |
| SlowDNS domain | Domain yang sudah Anda siapkan, misalnya `dns.example.org`. |
| SSH/upstream destination | `127.0.0.1:22` jika SSH berjalan pada port `22` di VPS yang sama. |

Installer membuat konfigurasi dan pasangan key secara otomatis, lalu
menjalankan layanan `slowdns`. Konfigurasi tersimpan di `/root/slowdns/slowdns.env`,
bersama key di folder yang sama. Menu dan pesan installer memakai bahasa Inggris.
Biarkan `install.sh` di folder tersebut selama layanan digunakan.

Dengan `auto`, listener menggunakan `:53`. Jika VPS hanya memiliki IPv4 atau
IPv6, keluarga alamat yang tersedia tetap dapat digunakan. IPv6 tertentu boleh
diisi sebagai `2001:db8::7` atau `[2001:db8::7]` pada prompt IP.
Jika port sudah dipakai DNS sistem, installer berhenti tanpa mematikannya.
Anda dapat memilih satu IP VPS yang portnya masih kosong.

Pada instalasi baru, layanan berjalan sebagai root tanpa sandbox tambahan.
Pastikan hanya root yang dapat mengubah folder pemasangan dan berkas di dalamnya.

Untuk melihat bantuan perintah:

```sh
bash /root/slowdns/install.sh --help
```

`-help` dan `-h` juga tersedia. Gunakan `install` untuk langsung memasang
tanpa membuka menu.

UDP `53` langsung memakai NOTRACK pada IP VPS yang dipilih agar trafik SlowDNS tidak
memenuhi tabel pelacakan koneksi. Aturannya dilepas saat layanan berhenti.
IPv4 memakai `iptables`, sedangkan IPv6 memakai `ip6tables`.
Installer tidak mengubah aturan izin firewall atau pengalihan port (NAT).
Jika memilih port lain, NOTRACK tidak dipasang.

### 3. Hubungkan HTTP Custom

Lihat public key server:

```sh
cat /root/slowdns/server.pub
```

Di pengaturan SlowDNS HTTP Custom, isi IP VPS, domain, dan public key tersebut,
lalu coba hubungkan. `server.key` adalah private key dan tetap disimpan di server.

### Memeriksa Layanan

```sh
systemctl status slowdns
journalctl -u slowdns -f
```

Perintah pertama menampilkan status layanan. Perintah kedua menampilkan log
terbaru; tekan Ctrl+C untuk selesai melihat log.

### Memasang Ulang

Sebelum mengganti `install.sh` atau binary dengan versi baru, hentikan layanan:

```sh
systemctl stop slowdns.service
```

Tunggu perintah berhasil agar aturan jaringan sebelumnya dibersihkan, lalu
unggah berkas baru tanpa mengganti `slowdns.env`, `server.key`, atau `server.pub`.

Jalankan kembali installer dan pilih **Install**. Pengaturan, key, dan unit
layanan yang sudah terpasang tetap digunakan. Layanan dimulai ulang sehingga
koneksi aktif akan terputus sementara.

### Menghapus Layanan

```sh
bash /root/slowdns/install.sh uninstall
```

Layanan dihentikan dan dihapus. Berkas konfigurasi, key, installer, dan
`slowdns` tetap tersimpan di folder pemasangan.

## English

### 1. Prepare the VPS and Files

Use a Linux VPS with systemd. Set up your SlowDNS domain to point to the VPS
and allow UDP port `53` in the VPS firewall and your server provider's panel.
To use both IPv4 and IPv6, allow that port for both.
Make sure no other service is using the port.

Log in to the VPS as root, then create the installation folder:

```sh
mkdir -p /root/slowdns
```

Extract the download on your computer, then upload `install.sh` and `slowdns`
to that folder:

```text
/root/slowdns/
  install.sh
  slowdns
```

### 2. Run the Installer

```sh
bash /root/slowdns/install.sh
```

Choose **1. Install**, then enter the settings below. Press Enter to use the
value shown in square brackets.

| Setting | Enter |
| --- | --- |
| Listener IP | Press Enter for `auto`: available IPv4 and IPv6. Enter one VPS IP to listen only on that address. |
| UDP port | `53`. |
| SlowDNS domain | The domain you set up, such as `dns.example.org`. |
| SSH/upstream destination | `127.0.0.1:22` if SSH runs on port `22` on the same VPS. |

The installer creates the configuration and key pair, then starts the
`slowdns` service. The configuration is saved in `/root/slowdns/slowdns.env`,
with the keys in the same folder. Installer menus and messages are in English.
Keep `install.sh` in that folder while the service is in use.

With `auto`, the listener uses `:53`. If the VPS only has IPv4 or IPv6,
it can still use the available address family. You can enter a specific IPv6
address as `2001:db8::7` or `[2001:db8::7]` at the IP prompt.
If system DNS is already using the port, the installer stops without stopping it.
You can choose one VPS IP where the port is free instead.

New installations run the service as root without an added sandbox.
Keep the installation folder and its files writable only by root.

To view command help:

```sh
bash /root/slowdns/install.sh --help
```

`-help` and `-h` also work. Use `install` to install directly without
opening the menu.

Direct UDP `53` uses NOTRACK on the selected VPS IPs to keep SlowDNS traffic out
of the connection tracking table. These rules are removed when the service
stops. IPv4 uses `iptables`, and IPv6 uses `ip6tables`.
The installer does not change firewall allow rules or port forwarding
(NAT). Other ports do not use NOTRACK.

### 3. Connect HTTP Custom

View the server's public key:

```sh
cat /root/slowdns/server.pub
```

In HTTP Custom's SlowDNS settings, enter the VPS IP address, domain, and
public key, then try connecting. `server.key` is the private key and stays
on the server.

### Check the Service

```sh
systemctl status slowdns
journalctl -u slowdns -f
```

The first command shows the service status. The second shows the latest logs;
press Ctrl+C when you finish viewing them.

### Reinstall

Before replacing `install.sh` or the binary with a new version, stop the service:

```sh
systemctl stop slowdns.service
```

Wait for the command to succeed so the previous network rules are removed, then
upload the new files without replacing `slowdns.env`, `server.key`, or `server.pub`.

Run the installer again and choose **Install**. Your saved settings, keys, and
existing service unit are reused. The service restarts, briefly disconnecting
active connections.

### Uninstall

```sh
bash /root/slowdns/install.sh uninstall
```

The service is stopped and removed. The configuration, keys, installer, and
`slowdns` remain in the installation folder.
