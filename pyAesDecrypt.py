#!/usr/bin/env python3
import os,sys,argparse,pyAesCrypt,zipfile,tempfile,threading,time
from queue import Queue,Empty

print(r"""
▂▃▅▇█▓▒ pyAesDecrypt ▒▓█▇▅▃▂
                     ~Bridger
""")

found_password=None
found_event=threading.Event()
attempts=0
attempts_lock=threading.Lock()
print_lock=threading.Lock()

def safe_print(*a,**k):
    with print_lock:
        print(*a,**k)
        sys.stdout.flush()

def is_zip(path):
    try:
        return zipfile.is_zipfile(path)
    except:
        return False

def decrypt_attempt(password,input_file,temp_path,buffer_size=64*1024):
    try:
        pyAesCrypt.decryptFile(input_file,temp_path,password,buffer_size)
        return True
    except ValueError:
        return False
    except Exception as e:
        raise

def worker(q,input_file,final_output_base,thread_id,zip_mode,verbose,report_every):
    global found_password,attempts
    while not found_event.is_set():
        try:
            pwd=q.get(timeout=1)
        except Empty:
            continue
        if pwd is None:
            q.task_done()
            break
        temp_fd,temp_path=tempfile.mkstemp(prefix=f"dec_t{thread_id}_",suffix=".tmp",dir=os.path.dirname(final_output_base) or ".")
        os.close(temp_fd)
        try:
            try:
                ok=decrypt_attempt(pwd.strip(),input_file,temp_path)
            except Exception as e:
                try:
                    os.remove(temp_path)
                except:
                    pass
                safe_print(f"[ERROR] Fatal error while trying '{pwd}': {e}")
                found_event.set()
                q.task_done()
                break
            with attempts_lock:
                attempts+=1
                if verbose and (attempts % report_every == 0):
                    safe_print(f"[INFO] Attempted {attempts} passwords...")
            if ok:
                try:
                    size=os.path.getsize(temp_path)
                except:
                    size=0
                if size==0:
                    try:
                        os.remove(temp_path)
                    except:
                        pass
                    q.task_done()
                    continue
                if zip_mode:
                    if not is_zip(temp_path):
                        try:
                            os.remove(temp_path)
                        except:
                            pass
                        q.task_done()
                        continue
                final_output=final_output_base
                try:
                    os.replace(temp_path,final_output)
                except Exception as e:
                    try:
                        os.remove(temp_path)
                    except:
                        pass
                    safe_print(f"[ERROR] Could not move temp file to final location: {e}")
                    q.task_done()
                    continue
                found_password=pwd
                safe_print(f"\n[SUCCESS] Password found: {pwd}")
                safe_print(f"[SUCCESS] Decrypted file: {final_output}")
                found_event.set()
                q.task_done()
                break
            else:
                try:
                    os.remove(temp_path)
                except:
                    pass
        finally:
            try:
                q.task_done()
            except:
                pass

def producer(wordlist_path,q,threads):
    try:
        with open(wordlist_path,'r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if found_event.is_set():
                    break
                pwd=line.rstrip('\n')
                if not pwd:
                    continue
                while True:
                    try:
                        q.put(pwd,timeout=1)
                        break
                    except:
                        if found_event.is_set():
                            break
        for _ in range(threads):
            q.put(None)
    except Exception as e:
        safe_print(f"[ERROR] Wordlist read error: {e}")
        for _ in range(threads):
            q.put(None)
        found_event.set()

def main():
    parser=argparse.ArgumentParser(description='')
    parser.add_argument('input_file',help='Encrypted input file')
    parser.add_argument('-w','--wordlist',required=True,help='Password wordlist file')
    parser.add_argument('-o','--output-dir',default='./decrypted',help='Output directory')
    parser.add_argument('-t','--threads',type=int,default=4,help='Number of threads')
    parser.add_argument('-v','--verbose',action='store_true',help='Enable verbose')
    parser.add_argument('--zip',action='store_true',help='Extract decrypted ZIP file automatically')
    parser.add_argument('--report-every',type=int,default=100,help='Report progress every N attempts')
    args=parser.parse_args()
    zip_mode=args.zip
    verbose=args.verbose
    if not os.path.isfile(args.input_file):
        safe_print(f"[ERROR] Input file not found: {args.input_file}")
        sys.exit(1)
    os.makedirs(args.output_dir,exist_ok=True)
    q=Queue(maxsize=10000)
    base=os.path.basename(args.input_file)
    if base.endswith('.aes'):
        base=base[:-4]
    if zip_mode and base.lower().endswith('.zip'):
        base=base[:-4]
    final_output=os.path.join(args.output_dir,f"{base}_decrypted.zip" if zip_mode else f"{base}_decrypted")
    safe_print(f"[INFO] Loaded (streaming) wordlist from {args.wordlist}")
    safe_print(f"[INFO] Starting brute force on {args.input_file}")
    safe_print(f"[INFO] Threads: {args.threads}, Output dir: {args.output_dir}, Verbose: {verbose}")
    safe_print("-"*50)
    prod=threading.Thread(target=producer,args=(args.wordlist,q,args.threads),daemon=True)
    prod.start()
    workers=[]
    for i in range(args.threads):
        t=threading.Thread(target=worker,args=(q,args.input_file,final_output,i,zip_mode,verbose,args.report_every),daemon=True)
        t.start()
        workers.append(t)
    try:
        while not found_event.is_set():
            alive=any(t.is_alive() for t in workers)
            if not alive:
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        safe_print("\n[INFO] Interrupted by user")
        found_event.set()
        sys.exit(1)
    for t in workers:
        t.join(timeout=1)
    safe_print("\n"+"="*50)
    if found_password:
        safe_print(f"[SUCCESS] Password: '{found_password}'")
        safe_print(f"[SUCCESS] Attempts: {attempts}")
        if os.path.exists(final_output):
            safe_print(f"[SUCCESS] Decrypted file at: {final_output} ({os.path.getsize(final_output)} bytes)")
            if zip_mode and is_zip(final_output):
                try:
                    extract_dir=os.path.join(args.output_dir,f"{base}_extracted")
                    os.makedirs(extract_dir,exist_ok=True)
                    with zipfile.ZipFile(final_output,'r') as z:
                        z.extractall(extract_dir)
                    safe_print(f"[SUCCESS] ZIP extracted to: {extract_dir}")
                except Exception as e:
                    safe_print(f"[WARNING] Could not extract ZIP: {e}")
    else:
        safe_print(f"[FAILURE] Password not found. Total attempts: {attempts}")

if __name__=='__main__':
    main()
