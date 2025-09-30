# pyAesDecrypt-Dictionary-Attack-for-AES-Encrypted-Files
pyAesDecrypt is a fast, streaming, multi-threaded bruteforce tool for files encrypted with pyAesCrypt. It was designed for lab and recovery scenarios: recover lost passwords for files you own or for legally authorized engagements. The tool supports memory-safe streaming of large wordlists, thread-safe decryption attempts using temporary files and atomic rename, automatic ZIP validation and extraction, and configurable progress reporting.

## Features
• Streaming wordlist reader (no need to load huge lists into memory)
• Multi-threaded worker pool for faster attempts
• Thread-safe atomic file handling to avoid corrupted/zero-byte outputs
• ZIP format validation and automatic extraction (--zip) (Optional)
• Configurable progress reporting (-v and --report-every)

## Requirements
• Python 3.8+ (or newer)
• pyAesCrypt Python package

## Usage
```python3 pyAesDecrypt.py -w /path/to/wordlist.txt [--zip] [-t THREADS] [-v] encrypted_file.aes```

If the file is also archived in zip format, you can use it as follows:

```python3 pyAesDecrypt.py -w /path/to/wordlist.txt [-t THREADS] [-v] --zip encrypted_file.zip.aes```

## Proof Of Concept
```python3 pyAesDecrypt.py -w /usr/share/wordlists/rockyou.txt --zip data.zip.aes -v```
<img width="1173" height="615" alt="image" src="https://github.com/user-attachments/assets/6354fd79-ce27-40da-b1bb-a27674cb2f59" />

