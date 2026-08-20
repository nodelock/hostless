#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import json
import time
import base64
import random
import string
import shutil
import asyncio
import platform
import signal
import threading
import subprocess
import datetime
import traceback
import requests
from pathlib import Path
from urllib.parse import urlparse, quote
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

# =========================== 环境变量 ===========================
UPLOAD_URL = os.environ.get('UPLOAD_URL', '')          # 节点或订阅上传地址
PROJECT_URL = os.environ.get('PROJECT_URL', '')        # 项目url,用于自动保活或上传订阅
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true'  # true开启自动保活,默认关闭
FILE_PATH_ENV = os.environ.get('FILE_PATH', '.cache')      # 运行目录,sub.txt保存路径
SUB_PATH = os.environ.get('SUB_PATH', 'sub')           # 订阅token
UUID = os.environ.get('UUID', 'ecc6fe55-232a-4767-aeb7-6aebc629b56e')  # UUID
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', 'vps.1492.eu.org')      # 哪吒面板域名
NEZHA_PORT = os.environ.get('NEZHA_PORT', '443')          # v1留空, v0填agent通信端口
NEZHA_KEY = os.environ.get('NEZHA_KEY', '7KLu5nbNsibi1swkzA')            # v1的NZ_CLIENT_SECRET或v0 agent密钥
ARGO_DOMAIN = os.environ.get('ARGO_DOMAIN', 'abasthan.1862.eu.org')        # Argo固定隧道域名
ARGO_AUTH = os.environ.get('ARGO_AUTH', 'eyJhIjoiMGUzYzZkNmU3ODEwZjQyZTlhMGRiYjQxYWZhNjQwZGUiLCJ0IjoiMTZjMzU1MTQtYjA1Zi00NTI4LTkwZWYtY2QwMmZjNzA2YzUxIiwicyI6IllqY3pORGMzTnpJdFlUYzNNQzAwT1RFMExXRmpOR1V0TXpBME9UTXdaakpqT0RoaCJ9')            # Argo固定隧道token或json
ARGO_PORT = int(os.environ.get('ARGO_PORT', '8001'))   # Argo隧道端口
S5_PORT = os.environ.get('S5_PORT', '')                # socks5端口
HY2_PORT = os.environ.get('HY2_PORT', '')              # hy2端口
REALITY_PORT = os.environ.get('REALITY_PORT', '')      # reality端口
CFIP = os.environ.get('CFIP', 'store.ubi.com')         # 优选ip或域名
CFPORT = int(os.environ.get('CFPORT', '443'))          # 优选端口
NAME = os.environ.get('NAME', 'Abasthan')                      # 节点名称
CHAT_ID = os.environ.get('CHAT_ID', '')                # Telegram chat_id
BOT_TOKEN = os.environ.get('BOT_TOKEN', '')            # Telegram bot_token
# 改进端口获取逻辑
raw_port = os.environ.get('PORT')
if raw_port:
    try:
        # 处理可能带有 /tcp 的端口字符串
        PORT = int(re.search(r'\d+', raw_port).group())
    except:
        PORT = 3000
else:
    PORT = 3000

# 强制开启日志以方便排查
SHOW_LOG = True 

# =========================== 日志控制 ===========================
def log(msg):
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def log_error(msg):
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: {msg}", file=sys.stderr)

def always_log(msg):
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()

# =========================== 全局变量 ===========================
private_key = ''
public_key = ''
sub_txt_content = ''
FILE_PATH = Path(FILE_PATH_ENV).resolve()

def generate_random_name(length=6):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

web_name = generate_random_name()
bot_name = generate_random_name()
npm_name = generate_random_name()
php_name = generate_random_name()

web_path = FILE_PATH / web_name
bot_path = FILE_PATH / bot_name
npm_path = FILE_PATH / npm_name
php_path = FILE_PATH / php_name
sub_path = FILE_PATH / 'sub.txt'
list_path = FILE_PATH / 'list.txt'
boot_log_path = FILE_PATH / 'boot.log'
config_path = FILE_PATH / 'config.json'
nezha_config_path = FILE_PATH / 'config.yaml'
cert_path = FILE_PATH / 'cert.pem'
key_path = FILE_PATH / 'private.key'

# =========================== 端口检查 ===========================
def is_valid_port(port):
    try:
        if port is None or port == '':
            return False
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return False
        return True
    except (ValueError, TypeError):
        return False

# =========================== X25519 密钥对生成 ===========================
def generate_x25519_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return {
        'privateKey': base64.urlsafe_b64encode(priv_bytes).decode().rstrip('='),
        'publicKey': base64.urlsafe_b64encode(pub_bytes).decode().rstrip('=')
    }

def generate_or_load_keypair():
    global private_key, public_key
    key_file_path = FILE_PATH / 'key.txt'
    if key_file_path.exists():
        content = key_file_path.read_text(encoding='utf-8')
        priv_match = re.search(r'PrivateKey:\s*(.*)', content)
        pub_match = re.search(r'PublicKey:\s*(.*)', content)
        if priv_match and pub_match:
            private_key = priv_match.group(1).strip()
            public_key = pub_match.group(1).strip()
            return
    keypair = generate_x25519_keypair()
    private_key = keypair['privateKey']
    public_key = keypair['publicKey']
    key_file_path.write_text(f'PrivateKey: {private_key}\nPublicKey: {public_key}\n', encoding='utf-8')

# =========================== TLS 证书生成 ===========================
FALLBACK_EC_KEY = '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49\nAwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa\n/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==\n-----END EC PRIVATE KEY-----\n'
FALLBACK_CERT = '-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy\nMDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h\naD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR\nBfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB\nAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+\neQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==\n-----END CERTIFICATE-----\n'

def ensure_tls_certificates(cert_file, key_file):
    if cert_file.exists() and key_file.exists():
        return
    cert_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        ec_private_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'bing.com')])
        cert_obj = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ec_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None))
            .not_valid_after((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)).replace(tzinfo=None))
            .sign(ec_private_key, hashes.SHA256())
        )
        key_pem = ec_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM)
        key_file.write_bytes(key_pem)
        cert_file.write_bytes(cert_pem)
    except Exception as e:
        log_error(f'Failed to generate TLS certificate: {e}')
        key_file.write_text(FALLBACK_EC_KEY, encoding='utf-8')
        cert_file.write_text(FALLBACK_CERT, encoding='utf-8')

def get_certificate_fingerprint(cert_file):
    try:
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        fingerprint = cert.fingerprint(hashes.SHA256())
        return ':'.join(f'{b:02X}' for b in fingerprint)
    except Exception as e:
        log_error(f'Failed to calculate certificate fingerprint: {e}')
        return ''

# =========================== 基础操作 ===========================
def create_directory():
    try:
        FILE_PATH.mkdir(parents=True, exist_ok=True)
        log(f"Directory {FILE_PATH} created/verified.")
    except Exception as e:
        log_error(f"Failed to create directory {FILE_PATH}: {e}")
        raise

def cleanup_old_files():
    preserve_files = {FILE_PATH / 'key.txt', cert_path, key_path}
    try:
        if not FILE_PATH.exists(): return
        for item in FILE_PATH.iterdir():
            if item in preserve_files: continue
            try:
                if item.is_file(): item.unlink()
                elif item.is_dir(): shutil.rmtree(item)
            except: pass
    except: pass

def get_system_architecture():
    arch = platform.machine().lower()
    if arch in ('arm', 'arm64', 'aarch64'): return 'arm'
    return 'amd'

def download_file(file_name, file_url):
    file_path = FILE_PATH / file_name
    try:
        log(f"Downloading {file_name} from {file_url}...")
        response = requests.get(file_url, stream=True, timeout=30)
        response.raise_for_status()
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        log(f'Download {file_name} success')
        return True
    except Exception as e:
        log_error(f'Download {file_name} failed: {e}')
        return False

def download_all_files():
    architecture = get_system_architecture()
    base_url = 'https://arm64.ssss.nyc.mn' if architecture == 'arm' else 'https://amd64.ssss.nyc.mn'
    downloads = [{'name': web_name, 'url': f'{base_url}/web'}, {'name': bot_name, 'url': f'{base_url}/bot'}]
    if NEZHA_SERVER and NEZHA_KEY:
        if NEZHA_PORT: downloads.append({'name': npm_name, 'url': f'{base_url}/agent'})
        else: downloads.append({'name': php_name, 'url': f'{base_url}/v1'})
    for item in downloads:
        download_file(item['name'], item['url'])

def authorize_files(file_names):
    for name in file_names:
        file_path = FILE_PATH / name
        if file_path.exists():
            try:
                os.chmod(str(file_path), 0o775)
            except Exception as e:
                log_error(f'Chmod failed for {name}: {e}')

def exec_cmd(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        return stdout + stderr
    except Exception as e:
        return str(e)

# =========================== 配置生成 ===========================
def argo_type():
    if not ARGO_AUTH or not ARGO_DOMAIN: return
    if 'TunnelSecret' in ARGO_AUTH:
        (FILE_PATH / 'tunnel.json').write_text(ARGO_AUTH, encoding='utf-8')
        try:
            data = json.loads(ARGO_AUTH)
            tunnel_id = data.get('TunnelID', '')
        except:
            tunnel_id = ''
        tunnel_yaml = f"tunnel: {tunnel_id}\ncredentials-file: {FILE_PATH / 'tunnel.json'}\nprotocol: http2\ningress:\n  - hostname: {ARGO_DOMAIN}\n    service: http://localhost:{ARGO_PORT}\n    originRequest:\n      noTLSVerify: true\n  - service: http_status:404"
        (FILE_PATH / 'tunnel.yml').write_text(tunnel_yaml, encoding='utf-8')

def generate_nezha_config():
    if not NEZHA_SERVER or not NEZHA_KEY or NEZHA_PORT: return
    nzport = NEZHA_SERVER.split(':')[-1] if ':' in NEZHA_SERVER else ''
    nezhatls = 'true' if nzport in {'443', '8443', '2096', '2087', '2083', '2053'} else 'false'
    config_yaml = f"client_secret: {NEZHA_KEY}\ndebug: false\ndisable_auto_update: true\ndisable_command_execute: false\ndisable_force_update: true\ndisable_nat: false\ndisable_send_query: false\ngpu: false\ninsecure_tls: true\nip_report_period: 1800\nreport_delay: 4\nserver: {NEZHA_SERVER}\nskip_connection_count: true\nskip_procs_count: true\ntemperature: false\ntls: {nezhatls}\nuuid: {UUID}"
    nezha_config_path.write_text(config_yaml, encoding='utf-8')

def generate_xray_config():
    config = {
        "log": {"access": "/dev/null", "error": "/dev/null", "loglevel": "none"},
        "inbounds": [
            {
                "tag": "vless-fallback-in", "listen": "::", "port": ARGO_PORT, "protocol": "vless",
                "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none"},
                "streamSettings": {"network": "ws", "wsSettings": {"path": "/vless-argo"}}
            }
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    }
    # 简化版配置，仅保证核心运行
    config_path.write_text(json.dumps(config, indent=2), encoding='utf-8')

# =========================== 运行逻辑 ===========================
def download_files_and_run():
    download_all_files()
    authorize_files([web_name, bot_name, npm_name, php_name])
    generate_nezha_config()
    
    # 启动二进制文件
    if NEZHA_SERVER and NEZHA_KEY:
        if NEZHA_PORT:
            exec_cmd(f"nohup {npm_path} -s {NEZHA_SERVER}:{NEZHA_PORT} -p {NEZHA_KEY} --disable-auto-update >/dev/null 2>&1 &")
        else:
            exec_cmd(f"nohup {php_path} -c {nezha_config_path} >/dev/null 2>&1 &")
    
    exec_cmd(f"nohup {web_path} -c {config_path} >/dev/null 2>&1 &")
    
    if bot_path.exists():
        if len(ARGO_AUTH) > 100: # Token
            exec_cmd(f"nohup {bot_path} tunnel --no-autoupdate --protocol http2 run --token {ARGO_AUTH} >/dev/null 2>&1 &")
        else:
            exec_cmd(f"nohup {bot_path} tunnel --no-autoupdate --protocol http2 --url http://localhost:{ARGO_PORT} >/dev/null 2>&1 &")

def start_server_process():
    try:
        log("Starting background processes...")
        create_directory()
        cleanup_old_files()
        argo_type()
        if is_valid_port(REALITY_PORT): generate_or_load_keypair()
        if is_valid_port(HY2_PORT): ensure_tls_certificates(cert_path, key_path)
        generate_xray_config()
        download_files_and_run()
        log("Background processes initiated.")
    except Exception as e:
        log_error(f"Error in start_server_process: {e}")
        traceback.print_exc()

# =========================== HTTP 服务 ===========================
class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == f'/{SUB_PATH}':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(b"App is running. Sub content will appear here.")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
    def log_message(self, format, *args): pass

# =========================== 入口 ===========================
if __name__ == '__main__':
    log(f"Application starting on port {PORT}...")
    
    try:
        # 启动后台任务
        t = threading.Thread(target=start_server_process, daemon=True)
        t.start()
        
        # 启动主 HTTP 服务器
        server = ThreadingHTTPServer(('0.0.0.0', PORT), RequestHandler)
        log(f"HTTP Server successfully bound to port {PORT}")
        server.serve_forever()
    except Exception as e:
        log_error(f"CRITICAL: Main loop failed: {e}")
        traceback.print_exc()
        sys.exit(1)
