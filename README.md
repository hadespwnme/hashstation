# Hashstation

A simple CLI tool to **analyze** and **crack** various hash types using the most commonly used passwords by Indonesians (according to NordPass), and as well as the famous `rockyou.txt`.

---

## Features

- 🔍 **Analyze** a single hash or multiple hashes from a file.
- 🧩 **Crack** a single hash.
- 📂 **Crack** all hashes in a file (with a specific mode or **all modes**).
- 🧾 **List** supported modes / algorithms.
- 🎛 **hashstation** more understand from hashid for analyze the hash.

---

## Requirements

- **Python** 3.8+
- **pip** to install dependencies

### Python Dependencies

- `rich`
- `kertash`

#### Quick Install

```bash
pip install -r requirements.txt
```

---

## Usage

### General Help

```bash
python hashstation.py -h
```

For show the help menu and subcommand.

### 1) List algorithm modes

```bash
python hashstation.py list
```

Show tables supported hash modes.

### 2) Analyze

#### a. Single hash

```bash
python hashstation.py analyze <HASH>
```

Example:
```bash
python hashstation.py analyze 5d41402abc4b2a76b9719d911017c592
```

#### b. From file

```bash
python hashstation.py analyze -f hashes.txt
```

> File should contain one hash per line.

### 3) Crack

#### a. Single hash with a specific mode

```bash
python hashstation.py crack -m <mode> <HASH>
```

Example:
```bash
python hashstation.py crack -m 0 5d41402abc4b2a76b9719d911017c592
```

> -m can be a code (e.g., 0, 1700) or name (e.g., md5, sha512)

#### b. File with **specific mode**

```bash
python hashstation.py crack -m <mode> -f hashes.txt
```

#### c. File with **all modes**

```bash
python hashstation.py crack -a -f hashes.txt
```

---

## Supported Hash Modes

| Mode  | Algorithm              | Description                      |
|-------|-------------------------|----------------------------------|
| 0     | MD5                      | Hash MD5                   |
| 100   | SHA1                     | SHA-1                           |
| 1400  | SHA256                   | SHA-256                         |
| 1700  | SHA512                   | SHA-512                         |
| 500   | md5crypt (Unix)          | MD5 crypt ($1$)                  |
| 1800  | sha512crypt (Unix)       | SHA-512 crypt ($6$)              |
| 3200  | bcrypt                   | bcrypt ($2a$, $2b$)              |
| 1600  | Apache MD5               | Apache $apr1$ MD5                |
| 1722  | SHA256crypt (Unix)       | SHA-256 crypt (Unix)             |
| 3910  | SHA1crypt (Unix)         | SHA-1 crypt (Unix)               |
| 1000  | NTLM                     | Windows NTLM hash               |
| 1100  | LAN Manager (LM)         | Windows LM hash                  |
| 2100  | DCC2                     | Domain Cached Credentials v2     |
| 5500  | NetNTLMv2                | Microsoft NetNTLMv2              |
| 5600  | NetNTLMv1                | Microsoft NetNTLMv1              |
| 7300  | IPB2+                    | Invision Power Board 2+          |
| 7400  | MyBB                     | MyBB forum                       |
| 7900  | Drupal7                  | Drupal 7 CMS                     |
| 2811  | phpass                   | WordPress, phpBB3 (PHPass)        |
| 3711  | MediaWiki B              | MediaWiki B hashing              |
| 5100  | Half MD5                  | MD5 setengah                     |
| 2600  | Double MD5               | md5(md5($pass))                  |
| 3500  | Triple MD5               | md5(md5(md5($pass)))              |
| 23    | Skype                    | Skype password hash              |
| 10    | MD5 + salt               | md5($pass.$salt)                 |


---
