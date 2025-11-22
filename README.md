# pyAesDecrypt -> Dictionary Attack for AES Encrypted Files
pyAesDecrypt is a fast, streaming, multi-threaded bruteforce tool for files or blobs encrypted with pyAesCrypt. It was designed for lab and recovery scenarios: recover lost passwords for files you own or for legally authorized engagements. The tool supports memory-safe streaming of large wordlists, thread-safe decryption attempts using temporary files and atomic rename, automatic ZIP validation and extraction, and configurable progress reporting.

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
```bash
python3 pyAesDecrypt.py -w /path/to/wordlist.txt [--zip] [-t THREADS] [-v] encrypted_file.aes
```
If the file is also archived in zip format, you can use it as follows:

```bash
python3 pyAesDecrypt.py -w /path/to/wordlist.txt [-t THREADS] [-v] --zip encrypted_file.zip.aes
```
If you have an encrypted blob, you can use it as follows:
```bash
python3 pyAesDecrypt.py -w /usr/share/wordlists/rockyou.txt --blob <DATA-BLOB>
```
## Proof Of Concept
**File Mode**
```bash
python3 pyAesDecrypt.py -w /usr/share/wordlists/rockyou.txt --zip data.zip.aes -v
```
<img width="1173" height="615" alt="image" src="https://github.com/user-attachments/assets/6354fd79-ce27-40da-b1bb-a27674cb2f59" />
**Blob Mode**
```bash
python3 pyAesDecrypt.py -w /usr/share/wordlists/rockyou.txt --blob <DATA-BLOB> -v
```
<img width="1903" height="507" alt="image" src="https://github.com/user-attachments/assets/b1e44b3e-2aa2-4cfc-9636-10add5902a29" />

If you want to see which words in the wordlist have been tried, use double verbose (-vv):
```bash
python3 pyAesDecrypt.py -w /usr/share/wordlists/rockyou.txt --blob <DATA-BLOB> -vv
```
<img width="1897" height="942" alt="image" src="https://github.com/user-attachments/assets/1c879e19-9796-454b-8f99-e2d58260c04e" />
