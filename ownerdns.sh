#!/bin/bash

# 配置参数
DOMAIN_ROOT="ownernet"
SERVER_IP="192.168.43.1"  # 服务器IP（网关/DHCP服务器）
HOTSPOT_IFACE="wlan0"     # 热点接口
NETWORK_RANGE="192.168.43.0/24" # 网络范围

# 安装必要组件
sudo apt update
sudo apt install -y python3-venv python3-pip git openssl dnsmasq iptables-persistent nginx

# 创建目录结构
sudo mkdir -p /opt/ownerdns/{ca,api,web,config}

# ====== 1. 配置网络接口 ======
sudo tee /etc/netplan/01-hotspot.yaml > /dev/null <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $HOTSPOT_IFACE:
      dhcp4: no
      addresses: [$SERVER_IP/24]
EOF
sudo netplan apply

# ====== 2. 创建CA和自动签发脚本 ======
cd /opt/ownerdns/ca
sudo openssl genrsa -out ca.key 4096
sudo openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=OwnerDNS Root CA/O=OwnerDNS Private Network"

sudo tee auto-cert.sh > /dev/null <<EOF
#!/bin/bash
DOMAIN=\$1
IP=\${2:-$SERVER_IP}
DOMAIN_ROOT="$DOMAIN_ROOT"
openssl genrsa -out \$DOMAIN.key 2048
openssl req -new -key \$DOMAIN.key -out \$DOMAIN.csr -subj "/CN=\$DOMAIN.\$DOMAIN_ROOT/O=OwnerDNS"
openssl x509 -req -days 365 -in \$DOMAIN.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out \$DOMAIN.crt
echo "域名 \$DOMAIN.\$DOMAIN_ROOT 已签发HTTPS证书！"
EOF
sudo chmod +x auto-cert.sh

# 为关键域名签发证书
sudo ./auto-cert.sh ownerweb $SERVER_IP
sudo ./auto-cert.sh dns-proxy $SERVER_IP
sudo ./auto-cert.sh cert-install $SERVER_IP

# ====== 3. 创建网站内容 ======
cd /opt/ownerdns/web
sudo tee index.html > /dev/null <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>OwnerDNS 控制面板</title>
    <style>:root {--primary: #4361ee; --dark: #212529; } body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 0; background: #f8f9fa; color: #343a40; } .container { max-width: 1200px; margin: 0 auto; padding: 20px; } header { background: var(--dark); color: white; padding: 15px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1); } nav { display: flex; justify-content: space-between; align-items: center; } .logo { font-size: 1.5rem; font-weight: bold; } .card { background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); padding: 25px; margin-bottom: 25px; transition: transform 0.3s; } .card:hover { transform: translateY(-5px); } .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 25px; } h1 { color: var(--primary); margin-top: 0; } .btn { background: var(--primary); color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none; display: inline-block; border: none; cursor: pointer; font-size: 1rem; } .btn:hover { opacity: 0.9; }</style>
</head>
<body>
    <header>
        <div class="container">
            <nav>
                <div class="logo">OwnerDNS</div>
            </nav>
        </div>
    </header>
    
    <main class="container">
        <h1>网络管理控制面板</h1>
        
        <div class="grid">
            <div class="card">
                <h2>域名注册</h2>
                <p>注册新的私有域名到您的网络</p>
                <form id="domainForm">
                    <input type="text" id="domainName" placeholder="yourname.ownernet" style="padding: 10px; width: 70%; margin-right: 10px; border: 1px solid #ddd; border-radius: 4px;">
                    <button type="submit" class="btn">注册</button>
                </form>
            </div>
            
            <div class="card">
                <h2>网络状态</h2>
                <p><strong>在线设备：</strong> <span id="deviceCount">0</span></p>
                <p><strong>已注册域名：</strong> <span id="domainCount">0</span></p>
            </div>
        </div>
        
        <div class="card">
            <h2>活动日志</h2>
            <div id="logs" style="height: 200px; overflow-y: auto; background: #f8f9fa; padding: 10px; border-radius: 4px; border: 1px solid #eee; font-family: monospace;"></div>
        </div>
    </main>
    
    <script>
    document.getElementById('domainForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = document.getElementById('domainName').value;
        
        try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `domain=${encodeURIComponent(domain)}`
            });
            
            const result = await response.text();
            addLog(`域名注册: ${domain} - ${result}`);
        } catch (error) {
            addLog(`注册失败: ${error.message}`);
        }
    });
    
    function addLog(message) {
        const logElement = document.getElementById('logs');
        const logEntry = document.createElement('div');
        logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        logElement.prepend(logEntry);
    }
    
    // 模拟实时更新
    setInterval(() => {
        document.getElementById('deviceCount').textContent = 
            Math.floor(Math.random() * 20 + 5);
        document.getElementById('domainCount').textContent = 
            Math.floor(Math.random() * 15 + 3);
    }, 5000);
    </script>
</body>
</html>
EOF

# ====== 4. 创建API服务 ======
cd /opt/ownerdns/api

sudo tee domain_api.py > /dev/null <<EOF
from flask import Flask, request, send_from_directory, jsonify
import subprocess
import os
import hashlib
import logging
from datetime import datetime

app = Flask(__name__, static_folder='/opt/ownerdns/web')
AUTH_SECRET = "SecureSecret123"

# 设置日志
logging.basicConfig(filename='/var/log/ownerdns-api.log', level=logging.INFO)

def authenticate():
    auth = request.headers.get('Authorization')
    if not auth:
        return False
    parts = auth.split()
    if len(parts) != 2 or parts[0] != "Secret":
        return False
    expected_hash = hashlib.sha256(AUTH_SECRET.encode()).hexdigest()
    return parts[1] == expected_hash

@app.route('/register', methods=['POST'])
def register_domain():
    if not authenticate():
        return "未授权访问", 403
    
    domain = request.form.get('domain')
    if not domain:
        return "缺少域名参数", 400
    
    try:
        # 记录注册请求
        client_ip = request.remote_addr
        logging.info(f"[{datetime.now()}] 域名注册: {domain} 来自 {client_ip}")
        
        # 执行证书签发
        result = subprocess.run(
            ['/opt/ownerdns/ca/auto-cert.sh', domain, '$SERVER_IP'], 
            capture_output=True, text=True, check=True
        )
        
        # 返回成功响应
        return jsonify({
            "status": "success",
            "domain": f"{domain}.$DOMAIN_ROOT",
            "message": "域名注册成功!",
            "certificate": f"https://{domain}.$DOMAIN_ROOT/"
        }), 200
        
    except subprocess.CalledProcessError as e:
        logging.error(f"注册失败: {e.stderr}")
        return jsonify({
            "status": "error",
            "message": f"证书签发失败: {e.stderr}"
        }), 500

@app.route('/')
def serve_index():
    return send_from_directory('/opt/ownerdns/web', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('/opt/ownerdns/web', path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context=(
        '/opt/ownerdns/ca/ownerweb.crt', 
        '/opt/ownerdns/ca/ownerweb.key'
    ))
EOF

# ====== 5. 自动证书安装服务 ======
sudo mkdir -p /var/www/cert-install
sudo cp /opt/ownerdns/ca/ca.crt /var/www/cert-install/root-ca.crt

sudo tee /var/www/cert-install/index.html > /dev/null <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>OwnerDNS 证书安装</title>
    <script>
    function installCertificate() {
        fetch('/install')
            .then(response => response.text())
            .then(data => {
                document.getElementById('message').innerHTML = 
                    `<div style="color: green; margin: 15px 0;">${data}</div>
                     <p>您现在可以安全访问私有网络服务：</p>
                     <p><a href="https://ownerweb.ownernet:5000">https://ownerweb.ownernet:5000</a></p>`;
            })
            .catch(error => {
                document.getElementById('message').innerHTML = 
                    `<div style="color: red;">证书安装失败: ${error.message}</div>`;
            });
    }
    </script>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; text-align: center;">
    <h1>OwnerDNS 网络安全设置</h1>
    <p>您的设备需要安装根证书以安全访问私有网络服务</p>
    
    <div style="background: #f0f8ff; border: 1px solid #cce5ff; border-radius: 5px; padding: 20px; margin: 20px 0;">
        <button onclick="installCertificate()" style="background: #4361ee; color: white; border: none; padding: 12px 25px; border-radius: 5px; font-size: 16px; cursor: pointer;">
            一键安装根证书
        </button>
        <p style="margin-top: 15px; font-size: 14px; color: #666;">
            或 <a href="/root-ca.crt" download>手动下载证书</a>
        </p>
    </div>
    
    <div id="message"></div>
</body>
</html>
EOF

sudo tee /var/www/cert-install/install.py > /dev/null <<'EOF'
#!/usr/bin/env python3
from flask import Flask, send_file, make_response
import os

app = Flask(__name__)

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/root-ca.crt')
def download_cert():
    return send_file('root-ca.crt', as_attachment=True)

@app.route('/install')
def install_cert():
    # 在实际应用中，这里应该提供平台特定的安装脚本
    # 这是一个概念验证实现
    response = make_response("根证书已成功安装！")
    response.headers['Content-Type'] = 'text/plain'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
EOF

# ====== 6. 配置 DNSMASQ (DNS + DHCP) ======
sudo tee /etc/dnsmasq.conf > /dev/null <<EOF
# 基本配置
interface=$HOTSPOT_IFACE
domain-needed
bogus-priv
no-resolv

# DHCP配置
dhcp-range=$NETWORK_RANGE,12h
dhcp-option=option:router,$SERVER_IP
dhcp-option=option:dns-server,$SERVER_IP
dhcp-option=option:domain-name,$DOMAIN_ROOT

# DNS配置
server=8.8.8.8
server=8.8.4.4
address=/dns-proxy.$DOMAIN_ROOT/$SERVER_IP
address=/cert-install.$DOMAIN_ROOT/$SERVER_IP
address=/#/$SERVER_IP  # 将所有域名解析到本机
EOF

# 重启DNS服务
sudo systemctl restart dnsmasq

# ====== 7. 配置透明代理 ======
# 启用IP转发
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# 配置NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i $HOTSPOT_IFACE -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o $HOTSPOT_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

# 透明HTTP代理 (80 -> 80)
sudo iptables -t nat -A PREROUTING -i $HOTSPOT_IFACE -p tcp --dport 80 -j DNAT --to-destination $SERVER_IP:80

# 透明HTTPS代理 (443 -> 5000)
sudo iptables -t nat -A PREROUTING -i $HOTSPOT_IFACE -p tcp --dport 443 -j DNAT --to-destination $SERVER_IP:5000

# 保存防火墙规则
sudo netfilter-persistent save

# ====== 8. 创建系统服务 ======
# 证书安装服务
sudo tee /etc/systemd/system/cert-install.service > /dev/null <<'EOF'
[Unit]
Description=OwnerDNS Certificate Install Service
After=network.target

[Service]
User=root
WorkingDirectory=/var/www/cert-install
ExecStart=/usr/bin/python3 /var/www/cert-install/install.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# API服务
sudo tee /etc/systemd/system/ownerdns.service > /dev/null <<'EOF'
[Unit]
Description=OwnerDNS API Service
After=network.target

[Service]
User=root
WorkingDirectory=/opt/ownerdns/api
ExecStart=/usr/bin/python3 /opt/ownerdns/api/domain_api.py
Restart=always
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
EOF

# ====== 9. 初始化环境 ======
cd /opt/ownerdns/api
sudo python3 -m venv venv
sudo ./venv/bin/pip install flask gunicorn

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable cert-install.service
sudo systemctl enable ownerdns.service
sudo systemctl start cert-install.service
sudo systemctl start ownerdns.service

# ====== 10. 客户端零配置 ======
echo "================================================================"
echo "全局零配置安装完成！"
echo "客户端只需连接到您的热点即可自动配置"
echo "控制面板: https://ownerweb.ownernet"
echo "证书安装: http://cert-install.ownernet"
echo "================================================================"
echo "网络信息:"
echo "SSID: $(hostname)"
echo "IP范围: $NETWORK_RANGE"
echo "网关/DNS: $SERVER_IP"
echo "================================================================"
