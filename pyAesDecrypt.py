#!/usr/bin/env python3
import os,sys,argparse,pyAesCrypt,zipfile,tempfile,time,base64,ctypes,shutil
import multiprocessing as mp
from queue import Empty

print(r"""
▂▃▅▇█▓▒ pyAesDecrypt ▒▓█▇▅▃▂
                        ~Bridger
""")

def safe_print(lock, *a, **k):
    with lock:
        print(*a, **k)
        sys.stdout.flush()

def is_zip(path):
    try:
        return zipfile.is_zipfile(path)
    except:
        return False


def decrypt_attempt_file(password,input_file,temp_path,buffer_size=64*1024):
    try:
        pyAesCrypt.decryptFile(input_file,temp_path,password,buffer_size)
        return True, None 
    except ValueError:
        return False, None 
    except Exception as e:
        raise


def worker(q, input_file_path, final_output_base, zip_mode, verbose_level, report_every, is_blob, temp_dir_base,
           found_event, attempts_counter, found_password_val, print_lock):
    
    temp_path = None
    file_renamed = False
    local_attempts = 0
    pid = os.getpid()

    try:
        temp_fd,temp_path=tempfile.mkstemp(prefix=f"dec_p{pid}_",suffix=".tmp",dir=temp_dir_base)
        os.close(temp_fd)

        while not found_event.is_set():
            try:
                pwd=q.get(timeout=0.1)
            except Empty:
                continue
            if pwd is None:
                q.put(None)
                break
            
            clean_pwd = pwd.strip()
            
            if verbose_level >= 2:
                safe_print(print_lock, f"[DEBUG] (PID {pid}) Trying: {clean_pwd}")
            
            try:
                try:
                    ok, _ = decrypt_attempt_file(clean_pwd, input_file_path, temp_path)
                except Exception as e:
                    safe_print(print_lock, f"[ERROR] (PID {pid}) Fatal error trying '{clean_pwd}': {e}")
                    found_event.set()
                    break
                    
                local_attempts += 1
                
                if verbose_level >= 1 and (local_attempts % report_every == 0):
                    with attempts_counter.get_lock():
                        attempts_counter.value += local_attempts
                        current_total = attempts_counter.value
                    safe_print(print_lock, f"[INFO] (PID {pid}) Attempted {local_attempts} (Total ~{current_total})...")
                    local_attempts = 0
                        
                if ok:
                    try:
                        size=os.path.getsize(temp_path)
                    except:
                        size=0
                    
                    if size==0:
                        continue
                    
                    if zip_mode and not is_blob:
                        if not is_zip(temp_path):
                            continue
                    
                    final_output=final_output_base
                    try:
                        shutil.move(temp_path,final_output)
                        file_renamed = True
                    except Exception as e:
                        safe_print(print_lock, f"[ERROR] (PID {pid}) Could not move temp file to final location: {e}")
                        continue
                    
                    with found_password_val.get_lock():
                        found_password_val.value = clean_pwd.encode('utf-8')
                    
                    safe_print(print_lock, f"\n[SUCCESS] (PID {pid}) Password found: {clean_pwd}")
                    safe_print(print_lock, f"[SUCCESS] (PID {pid}) Decrypted output: {final_output}")
                    found_event.set()
                    break
                
            finally:
                pass
    finally:
        if local_attempts > 0:
            with attempts_counter.get_lock():
                attempts_counter.value += local_attempts
        
        if temp_path and os.path.exists(temp_path) and not file_renamed:
            try:
                os.remove(temp_path)
            except:
                pass

def producer(wordlist_path, q, threads, found_event, print_lock):
    try:
        with open(wordlist_path,'r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if found_event.is_set():
                    break
                pwd=line.rstrip('\n')
                if not pwd:
                    continue
                q.put(pwd)
        
        for _ in range(threads):
            q.put(None)
    except Exception as e:
        safe_print(print_lock, f"[ERROR] Wordlist read error: {e}")
        for _ in range(threads):
            q.put(None)
        found_event.set()

def main():
    parser=argparse.ArgumentParser(description='A high-performance, multiprocessing dictionary attack tool for pyAesCrypt.')
    parser.add_argument('input_data',help='Encrypted file path OR Base64-encoded encrypted data blob if --blob is used.')
    parser.add_argument('-w','--wordlist',required=True,help='Password wordlist file')
    parser.add_argument('-o','--output-dir',default='./decrypted',help='Directory to save the decrypted file/blob')
    parser.add_argument('-t','--threads',type=int,default=os.cpu_count() or 1,help=f'Number of processes (Default: {os.cpu_count() or 1})')
    parser.add_argument('-v','--verbose',action='count',default=0,help='Increase verbosity level (-v for periodic reports, -vv for all tries)')
    parser.add_argument('--zip',action='store_true',help='Assume decrypted file is a ZIP and validate it')
    parser.add_argument('--blob',action='store_true',help='Specify input is a Base64-encoded data blob, not a file path.')
    parser.add_argument('--report-every',type=int,default=200,help='Report progress every N attempts (per-process, needs -v)')
    parser.add_argument('--temp-dir',default=None,help='Directory for temp files (Default: /dev/shm if available, else output dir)')
    args=parser.parse_args()

    zip_mode=args.zip
    is_blob=args.blob
    
    input_data_arg = args.input_data
    input_for_worker = None
    temp_blob_path = None
    base = None
    final_output = None

    os.makedirs(args.output_dir,exist_ok=True)
    
    if args.temp_dir:
        temp_dir_base = args.temp_dir
    elif sys.platform == 'linux' and os.path.exists('/dev/shm'):
        temp_dir_base = '/dev/shm'
    else:
        temp_dir_base = args.output_dir
    
    print_lock = mp.Lock()
    
    if is_blob:
        safe_print(print_lock, "[INFO] Mode: Data Blob Decryption.")
        try:
            input_data_bytes = base64.b64decode(input_data_arg)
            temp_fd, temp_blob_path = tempfile.mkstemp(prefix="blob_input_", suffix=".aes", dir=temp_dir_base)
            with os.fdopen(temp_fd, 'wb') as f:
                f.write(input_data_bytes)
            
            input_for_worker = temp_blob_path
            base="encrypted_blob"
            final_output=os.path.join(args.output_dir,f"{base}_decrypted.bin")
            
        except Exception as e:
            safe_print(print_lock, f"[ERROR] Base64 decoding or temp file creation error: {e}")
            if temp_blob_path and os.path.exists(temp_blob_path):
                os.remove(temp_blob_path)
            sys.exit(1)
            
    else:
        safe_print(print_lock, "[INFO] Mode: File Decryption.")
        if not os.path.isfile(input_data_arg):
            safe_print(print_lock, f"[ERROR] Input file not found: {input_data_arg}")
            sys.exit(1)
            
        input_for_worker = input_data_arg
        base=os.path.basename(input_for_worker)
        if base.endswith('.aes'):
            base=base[:-4]
        if zip_mode and base.lower().endswith('.zip'):
            base=base[:-4]
        final_output=os.path.join(args.output_dir,f"{base}_decrypted.zip" if zip_mode else f"{base}_decrypted")
        
    q = mp.Queue(maxsize=args.threads * 200)
    found_event = mp.Event()
    attempts_counter = mp.Value('L', 0)
    found_password_val = mp.Array('c', 2048)
    
    safe_print(print_lock, f"[INFO] Using temp directory: {temp_dir_base}")
    safe_print(print_lock, f"[INFO] Loaded (streaming) wordlist from {args.wordlist}")
    safe_print(print_lock, f"[INFO] Starting brute force on {'data blob' if is_blob else input_for_worker}")
    safe_print(print_lock, f"[INFO] Processes: {args.threads}, Output dir: {args.output_dir}, Verbosity: {args.verbose}")
    safe_print(print_lock, "-"*50)
    
    prod = mp.Process(target=producer,args=(args.wordlist,q,args.threads,found_event,print_lock),daemon=True)
    prod.start()
    
    workers=[]
    for i in range(args.threads):
        t=mp.Process(target=worker,args=(q,input_for_worker,final_output,zip_mode,args.verbose,args.report_every,is_blob,temp_dir_base,
                                         found_event,attempts_counter,found_password_val,print_lock),daemon=True)
        t.start()
        workers.append(t)
        
    try:
        while not found_event.is_set():
            alive=any(t.is_alive() for t in workers)
            if not alive:
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        safe_print(print_lock, "\n[INFO] Interrupted by user")
        found_event.set()
        
    for t in workers:
        t.join(timeout=0.1)
        if t.is_alive():
            t.terminate()
        
    prod.terminate()
        
    safe_print(print_lock, "\n"+"="*50)
    
    total_attempts = attempts_counter.value
    found_password = found_password_val.value.decode('utf-8')

    if found_password:
        safe_print(print_lock, f"[SUCCESS] Password: '{found_password}'")
        safe_print(print_lock, f"[SUCCESS] Total Attempts: {total_attempts}")
        
        if os.path.exists(final_output):
            size = os.path.getsize(final_output)
            safe_print(print_lock, f"[SUCCESS] Decrypted output at: {final_output} ({size} bytes)")
            
            if not is_blob and zip_mode and is_zip(final_output):
                try:
                    extract_dir=os.path.join(args.output_dir,f"{base}_extracted")
                    os.makedirs(extract_dir,exist_ok=True)
                    with zipfile.ZipFile(final_output,'r') as z:
                        z.extractall(extract_dir)
                    safe_print(print_lock, f"[SUCCESS] ZIP extracted to: {extract_dir}")
                except Exception as e:
                    safe_print(print_lock, f"[WARNING] Could not extract ZIP: {e}")
                    
    else:
        safe_print(print_lock, f"[FAILURE] Password not found. Total attempts: {total_attempts}")

    if temp_blob_path and os.path.exists(temp_blob_path):
        try:
            os.remove(temp_blob_path)
        except Exception as e:
            safe_print(print_lock, f"[WARNING] Could not delete temp blob file: {e}")

if __name__=='__main__':
    mp.freeze_support()
    main()
