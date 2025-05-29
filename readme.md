# 🔐 Mag-Security

A powerful command-line Python based **Personal Security Toolkit** for securely encrypting and decrypting text messages or spreadsheet data. This tool also supports reading from local Excel files or public Google Sheets.



## 📦 Features

* 🔑 **AES Encryption** with password-derived keys using PBKDF2-HMAC-SHA256
* 📤 **Encrypt any message** directly from the command-line
* 📄 **Encrypt & decrypt entire spreadsheets**
* 🔐 **Secure password prompt** (your input stays hidden)
* 🧮 **Supports local `.xlsx` files** and **Google Sheets (Xlsx export)**
* 🧾 **Formatted terminal output** for spreadsheet previews



## Installation:
```bash
pip install -r requirements.txt
python3 magSecurity.py
```

## Download & Release:
- <a href="">Linux Release (deb)</a> 
- <a href="">Windows Release (.exe)</a> 

<br>

## Features & Options:


### Encryption Opt:

* **Encrypt Single Message**: Enter a message and get an encrypted string.
* **Encrypt Sheet Data**: Provide an Excel or Google Sheet link to encrypt entire datasets.

### Decryption Opt:

* **Decrypt Encrypted String**: Paste in an encrypted string and get the original message back.
* **Decrypt Encrypted Sheet**: Load previously encrypted sheet data and decrypt it into readable format.

### File Support:

* `.xlsx` files (read/write support)
* Google Sheets (Public URL)
* Planning For File Encryption (**Coming Soon**)



### Folder Structure:

- `encrypted_outpus/`
- `decrypted_outpus/`


<br>

## 🔐 CryptoGraphy Information:
- Encrypted on: 2025-05-29
- Algorithm: AES-256-CBC
- Key Derivation: PBKDF2HMAC (SHA256, 100k iterations)
- Salt: first 16 bytes of b64 string
- IV: next 16 bytes
- Ciphertext: remainder
- Password required



## ⚠️ Notes

* Your password is **not recoverable**. If you forget it, you won't be able to decrypt the data.
* Always keep a backup of your decrypted data if it’s important.
* The program handles Ctrl+C safely without crashing.

