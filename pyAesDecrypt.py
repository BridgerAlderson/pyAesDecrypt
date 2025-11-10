#!/usr/bin/env python3
import os,sys,argparse,pyAesCrypt,zipfile,tempfile,threading,time,base64
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


def decrypt_attempt_file(password,input_file,temp_path,buffer_size=64*1024):
    try:
        pyAesCrypt.decryptFile(input_file,temp_path,password,buffer_size)
        return True, None 
    except ValueError:
        return False, None 
    except Exception as e:
        raise


def decrypt_attempt_blob(password,encrypted_data,buffer_size=64*1024):
    try:
        
        decrypted_data = pyAesCrypt.decryptData(encrypted_data, password, buffer_size)
        return True, decrypted_data
    except ValueError:
        return False, None 
    except Exception as e:
        raise

def worker(q,input_data,final_output_base,thread_id,zip_mode,verbose,report_every,is_blob):
    global found_password,attempts
    temp_path = None
    decrypted_blob_data = None
    
    while not found_event.is_set():
        try:
            pwd=q.get(timeout=1)
        except Empty:
            continue
        if pwd is None:
            q.task_done()
            break
        
        
        if not is_blob:
            temp_fd,temp_path=tempfile.mkstemp(prefix=f"dec_t{thread_id}_",suffix=".tmp",dir=os.path.dirname(final_output_base) or ".")
            os.close(temp_fd)

        try:
            try:
                if is_blob:
                    ok, decrypted_blob_data = decrypt_attempt_blob(pwd.strip(), input_data)
                else:
                    ok, _ = decrypt_attempt_file(pwd.strip(), input_data, temp_path)
            except Exception as e:
                
                if not is_blob:
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
                if is_blob:
                    
                    final_output = final_output_base
                    try:
                        with open(final_output, 'wb') as f:
                            f.write(decrypted_blob_data)
                    except Exception as e:
                        safe_print(f"[ERROR] Could not save decrypted blob: {e}")
                        q.task_done()
                        continue
                else:
                    
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
                safe_print(f"[SUCCESS] Decrypted output: {final_output}")
                found_event.set()
                q.task_done()
                break
            else:
                
                if not is_blob:
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
    parser=argparse.ArgumentParser(description='pyAesCrypt ile şifrelenmiş dosya veya veri bloğunu sözlük saldırısı ile çözme aracı.')
    parser.add_argument('input_data',help='Şifrelenmiş dosya yolu VEYA --blob kullanılıyorsa, Base64 kodlanmış şifreli veri bloğu.')
    parser.add_argument('-w','--wordlist',required=True,help='Şifre sözlük dosyası')
    parser.add_argument('-o','--output-dir',default='./decrypted',help='Çözülmüş dosyanın/bloğun kaydedileceği dizin')
    parser.add_argument('-t','--threads',type=int,default=4,help='İş parçacığı sayısı')
    parser.add_argument('-v','--verbose',action='store_true',help='Ayrıntılı çıktıları etkinleştir')
    parser.add_argument('--zip',action='store_true',help='Çözülen dosyanın bir ZIP arşivi olduğunu varsay ve otomatik olarak aç')
    parser.add_argument('--blob',action='store_true',help='Girişin bir dosya yolu değil, Base64 kodlanmış şifreli veri bloğu olduğunu belirtir.')
    parser.add_argument('--report-every',type=int,default=100,help='Her N denemede bir ilerlemeyi rapor et')
    args=parser.parse_args()

    zip_mode=args.zip
    verbose=args.verbose
    is_blob=args.blob
    
    input_data = args.input_data 

    if is_blob:
        safe_print("[INFO] Çalışma modu: Veri Bloğu (Blob) Çözme.")
        try:
            
            input_data_bytes = base64.b64decode(input_data)
            
            input_for_worker = input_data_bytes
            
            base="encrypted_blob"
            final_output=os.path.join(args.output_dir,f"{base}_decrypted.bin")
            
        except Exception as e:
            safe_print(f"[ERROR] Base64 çözme hatası: {e}")
            sys.exit(1)
            
    else:
        
        safe_print("[INFO] Çalışma modu: Dosya Çözme.")
        if not os.path.isfile(input_data):
            safe_print(f"[ERROR] Input file not found: {input_data}")
            sys.exit(1)
            
       
        input_for_worker = input_data
        
        base=os.path.basename(input_data)
        if base.endswith('.aes'):
            base=base[:-4]
        if zip_mode and base.lower().endswith('.zip'):
            base=base[:-4]
        final_output=os.path.join(args.output_dir,f"{base}_decrypted.zip" if zip_mode else f"{base}_decrypted")
        
        
    os.makedirs(args.output_dir,exist_ok=True)
    q=Queue(maxsize=10000)
    
    safe_print(f"[INFO] Loaded (streaming) wordlist from {args.wordlist}")
    safe_print(f"[INFO] Starting brute force on {'veri bloğu' if is_blob else args.input_data}")
    safe_print(f"[INFO] Threads: {args.threads}, Output dir: {args.output_dir}, Verbose: {verbose}")
    safe_print("-"*50)
    
    prod=threading.Thread(target=producer,args=(args.wordlist,q,args.threads),daemon=True)
    prod.start()
    
    workers=[]
    for i in range(args.threads):
        
        t=threading.Thread(target=worker,args=(q,input_for_worker,final_output,i,zip_mode,verbose,args.report_every,is_blob),daemon=True)
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
            size = os.path.getsize(final_output)
            safe_print(f"[SUCCESS] Decrypted output at: {final_output} ({size} bytes)")
            
            
            if not is_blob and zip_mode and is_zip(final_output):
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
