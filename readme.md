Here’s a clean and attractive `README.md` file based on your script. It’s written with clarity in mind for developers, while still showcasing the script’s features without relying on too many visuals:

---

# 🔐 Personal Security Toolkit

A simple yet powerful command-line Python application for securely encrypting and decrypting text messages or spreadsheet data. This tool also supports reading from local Excel files or public Google Sheets.

## 📦 Features

* 🔑 **AES Encryption** with password-derived keys using PBKDF2-HMAC-SHA256
* 📤 **Encrypt any message** directly from the command-line
* 📄 **Encrypt & decrypt entire spreadsheets**
* 🔐 **Secure password prompt** (your input stays hidden)
* 🧮 **Supports local `.xlsx` files** and **Google Sheets (CSV export)**
* 🧾 **Formatted terminal output** for spreadsheet previews
* 💥 **Safe exit** on Ctrl+C

## 📁 Folder Structure

The program automatically creates two folders in your working directory:

```
encrypted_outpus/
decrypted_outpus/
```

Encrypted and decrypted files will be saved here.

## 📚 Requirements

* Python 3.7+
* `openpyxl`
* `cryptography`
* `requests`

Install dependencies:

```bash
pip install -r requirements.txt
```

If no `requirements.txt`, use:

```bash
pip install openpyxl cryptography requests
```

## 🚀 How to Use

1. **Run the Script**

```bash
python main.py
```

2. **Enter a Password**

You will be asked to enter a password. This will be used to encrypt/decrypt your data. Do **not forget** it!

3. **Choose an Option**

* `1` Encrypt data
* `2` Decrypt data
* `3` Start password authentication
* `4` Exit

### 🔐 Encryption Options

* **Encrypt Single Message**: Enter a message and get an encrypted string.
* **Encrypt Sheet Data**: Provide an Excel or Google Sheet link to encrypt entire datasets.

### 🔓 Decryption Options

* **Decrypt Encrypted String**: Paste in an encrypted string and get the original message back.
* **Decrypt Encrypted Sheet**: Load previously encrypted sheet data and decrypt it into readable format.

## 🔎 File Support

* `.xlsx` files (read/write support)
* Google Sheets (CSV export through public URL)

## 💡 Example Google Sheet URL

```
https://docs.google.com/spreadsheets/d/1a2b3c4d5e6f7g8h9i0j/export?format=csv
```

The script extracts the file ID automatically.

## ⚠️ Notes

* Your password is **not recoverable**. If you forget it, you won't be able to decrypt the data.
* Always keep a backup of your decrypted data if it’s important.
* The program handles Ctrl+C safely without crashing.

## 🧼 Clean Terminal Interface

This app works on both **Windows** and **Unix-based systems**, clearing the screen for a clean user experience every time you return to the main menu.

---

**Created with focus on security and usability. Stay secure!**
Feel free to fork, modify, or contribute.

---

Let me know if you want this `README.md` saved to a file or formatted in a particular way (like GitHub-flavored with badges or emojis).
