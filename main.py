# -*- coding: utf-8 -*-

import os
import json
import socket
import ipaddress
import logging
import hashlib
import hmac
import time
import argparse
import threading
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

import psutil
import requests
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

# =================== 路径配置 ===================
HOME_DIR = Path.home()
TEMP_DIR = tempfile.gettempdir()
CURRENT_DIR = Path(__file__).parent
STATIC_PATH = CURRENT_DIR / "static"
CONFIG_FILE = HOME_DIR / ".edgeonev6.config.yaml"
LOG_FILE = Path(TEMP_DIR) / "edgeonev6.log"

# =================== 日志配置 ===================
def setup_logging():
    _logger = logging.getLogger("edgeonev6")
    _logger.setLevel(logging.INFO)

    file_handler = RotatingFileHandler(
        str(LOG_FILE), maxBytes=200 * 1024, backupCount=1, encoding="utf-8"
    )
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

    for handler in [file_handler, console_handler]:
        handler.setFormatter(formatter)
        handler.setLevel(logging.INFO)
        if not _logger.hasHandlers():
            _logger.addHandler(handler)

    return _logger

logger = setup_logging()

# =================== 全局状态 ===================
app_status = {
    "status": "idle",
    "message": "",
    "current_ipv6": "",
    "domains": [],  # 每个域名的更新状态
    "last_update": ""
}


# =================== 配置管理 ===================
def read_config():
    """读取配置文件"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"配置文件读取失败: {e}")
    return {}


def save_config(config):
    """保存配置文件"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True)
        return True
    except Exception as e:
        logger.error(f"配置文件保存失败: {e}")
        return False


# =================== 腾讯云API客户端 ===================
class TencentCloudClient:
    """腾讯云API客户端（原生签名实现）"""

    def __init__(self, secret_id, secret_key, service='teo', version='2022-09-01'):
        self.service = service
        self.host = f'{service}.tencentcloudapi.com'
        self.version = version
        self.algorithm = 'TC3-HMAC-SHA256'
        self.content_type = 'application/json; charset=utf-8'
        self.secret_id = secret_id
        self.secret_key = secret_key

    def _sign(self, key, message):
        return hmac.new(key, message.encode('utf-8'), hashlib.sha256).digest()

    def _make_signature(self, action, body):
        """生成API签名"""
        timestamp = int(time.time())
        date = datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d')
        payload = json.dumps(body)

        hashed_payload = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        canonical_headers = f'content-type:{self.content_type}\nhost:{self.host}\nx-tc-action:{action.lower()}\n'
        signed_headers = 'content-type;host;x-tc-action'
        canonical_request = f'POST\n/\n\n{canonical_headers}\n{signed_headers}\n{hashed_payload}'

        credential_scope = f'{date}/{self.service}/tc3_request'
        hashed_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        string_to_sign = f'{self.algorithm}\n{timestamp}\n{credential_scope}\n{hashed_request}'

        secret_date = self._sign(('TC3' + self.secret_key).encode('utf-8'), date)
        secret_service = self._sign(secret_date, self.service)
        secret_signing = self._sign(secret_service, 'tc3_request')
        signature = hmac.new(secret_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        authorization = (
            f'{self.algorithm} '
            f'Credential={self.secret_id}/{credential_scope}, '
            f'SignedHeaders={signed_headers}, '
            f'Signature={signature}'
        )

        return {
            'Authorization': authorization,
            'Content-Type': self.content_type,
            'Host': self.host,
            'X-TC-Action': action,
            'X-TC-Version': self.version,
            'X-TC-Timestamp': str(timestamp)
        }

    def request(self, action, body):
        """发送API请求"""
        headers = self._make_signature(action, body)
        response = requests.post(
            f'https://{self.host}',
            headers=headers,
            json=body,
            timeout=30
        ).json()
        return response

    def modify_acceleration_domain(self, zone_id, domain_name, origin):
        """修改加速域名源站"""
        body = {
            "ZoneId": zone_id,
            "DomainName": domain_name,
            "OriginInfo": {
                "OriginType": "IP_DOMAIN",
                "Origin": origin
            }
        }
        response = self.request('ModifyAccelerationDomain', body)
        error = response.get("Response", {}).get("Error", {})
        if error:
            return False, error.get("Message", "未知错误"), error.get("Code", "")
        return True, "更新成功", ""

    def describe_acceleration_domains(self, zone_id, domain_name):
        """查询加速域名配置"""
        body = {
            "ZoneId": zone_id,
            "Filters": [
                {"Name": "domain-name", "Values": [domain_name]}
            ]
        }
        response = self.request('DescribeAccelerationDomains', body)
        domains = response.get("Response", {}).get("AccelerationDomains", [])
        if domains:
            return domains[0].get("OriginDetail", {}).get("Origin", "")
        return ""


# =================== IPv6工具类 ===================
class IPv6Tool:
    """IPv6地址获取工具"""

    def __init__(self, interface_name="", check_reachable=False):
        self.interface_name = interface_name
        self.check_reachable = check_reachable

    def get_ipv6_address(self):
        """获取公网IPv6地址"""
        ipv6_list = []
        addrs = psutil.net_if_addrs()

        for iface, addr_list in addrs.items():
            if self.interface_name and iface != self.interface_name:
                continue

            for addr in addr_list:
                if addr.family == socket.AF_INET6:
                    ip = addr.address.split('%')[0]
                    if self._is_public_ipv6(ip):
                        if self.check_reachable:
                            if self._check_ipv6_reachable(ip):
                                ipv6_list.append(ip)
                        else:
                            ipv6_list.append(ip)

        if ipv6_list:
            return ipv6_list[0]
        return None

    @staticmethod
    def _is_public_ipv6(ip):
        """判断是否为公网IPv6地址"""
        try:
            addr = ipaddress.IPv6Address(ip)
            return not (
                addr.is_link_local or
                addr.is_private or
                addr.is_loopback or
                addr.is_unspecified or
                addr.is_multicast or
                addr.is_reserved
            )
        except ValueError:
            return False

    def _check_ipv6_reachable(self, ip):
        """检测IPv6地址是否公网可达"""
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        try:
            res = requests.get(
                f"https://ipw.cn/api/ping/ipv6/{ip}/1/all",
                headers={"User-Agent": user_agent},
                timeout=10
            )
            if '"lossPacket":0' in res.text:
                logger.info(f"IPv6 {ip} 公网可达 (ipw.cn)")
                return True
        except Exception as e:
            logger.debug(f"ipw.cn 检测失败: {e}")

        try:
            res = requests.get(
                f"https://ping6.network/index.php?host={ip.replace(':', '%3A')}",
                headers={"User-Agent": user_agent},
                timeout=15
            )
            if ', 0% packet loss' in res.text:
                logger.info(f"IPv6 {ip} 公网可达 (ping6.network)")
                return True
        except Exception as e:
            logger.debug(f"ping6.network 检测失败: {e}")

        logger.warning(f"IPv6 {ip} 公网不可达")
        return False

    @staticmethod
    def list_interfaces():
        """列出所有网卡"""
        return list(psutil.net_if_addrs().keys())


# =================== 更新任务 ===================
def update_task():
    """执行更新任务"""
    global app_status
    config = read_config()

    secret_id = config.get("SecretId", "")
    secret_key = config.get("SecretKey", "")
    domains = config.get("Domains", [])
    interface_name = config.get("InterfaceName", "")
    check_reachable = config.get("CheckReachable", False)

    app_status["status"] = "running"
    app_status["message"] = "正在更新..."
    app_status["domains"] = []

    if not secret_id or not secret_key:
        app_status["status"] = "error"
        app_status["message"] = "未配置腾讯云密钥"
        logger.error("未配置腾讯云密钥")
        return

    if not domains:
        app_status["status"] = "error"
        app_status["message"] = "未配置加速域名"
        logger.error("未配置加速域名")
        return

    # 获取IPv6地址
    ipv6_tool = IPv6Tool(interface_name, check_reachable)
    ipv6 = ipv6_tool.get_ipv6_address()

    if not ipv6:
        app_status["status"] = "error"
        app_status["message"] = "无法获取公网IPv6地址"
        app_status["current_ipv6"] = ""
        logger.error("无法获取公网IPv6地址")
        return

    app_status["current_ipv6"] = ipv6
    logger.info(f"获取到IPv6地址: {ipv6}")

    # 创建API客户端
    client = TencentCloudClient(secret_id, secret_key)

    # 遍历所有域名进行更新
    success_count = 0
    error_count = 0
    domain_results = []

    for domain_config in domains:
        zone_id = domain_config.get("ZoneId", "")
        domain_name = domain_config.get("DomainName", "")

        if not zone_id or not domain_name:
            continue

        # 查询当前源站配置
        current_origin = client.describe_acceleration_domains(zone_id, domain_name)

        if current_origin and current_origin == ipv6:
            logger.info(f"[{domain_name}] IPv6地址未变化，无需更新")
            domain_results.append({
                "domain": domain_name,
                "success": True,
                "message": "无需更新"
            })
            success_count += 1
            continue

        # 更新源站
        logger.info(f"正在更新 {domain_name} 的源站地址为 {ipv6}...")
        success, message, code = client.modify_acceleration_domain(zone_id, domain_name, ipv6)

        if success:
            logger.info(f"[{domain_name}] 更新成功")
            domain_results.append({
                "domain": domain_name,
                "success": True,
                "message": "更新成功"
            })
            success_count += 1
        else:
            logger.error(f"[{domain_name}] 更新失败: {message} ({code})")
            domain_results.append({
                "domain": domain_name,
                "success": False,
                "message": f"{message}"
            })
            error_count += 1

    # 更新状态
    app_status["domains"] = domain_results
    app_status["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if error_count == 0:
        app_status["status"] = "success"
        app_status["message"] = f"全部更新完成 ({success_count}个域名)"
    elif success_count == 0:
        app_status["status"] = "error"
        app_status["message"] = f"全部更新失败 ({error_count}个域名)"
    else:
        app_status["status"] = "success"
        app_status["message"] = f"部分更新成功 ({success_count}成功, {error_count}失败)"


# =================== 定时调度器 ===================
class TaskScheduler:
    def __init__(self, interval_min=15):
        self.interval_min = interval_min
        self.scheduler_thread = None
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()

    def scheduler_loop(self):
        while not self.stop_flag.is_set():
            try:
                update_task()
            except Exception as e:
                logger.error(f"任务执行异常: {e}")

            for _ in range(self.get_interval() * 60):
                if self.stop_flag.is_set():
                    return
                time.sleep(1)

    def get_interval(self):
        with self.lock:
            return self.interval_min

    def set_interval(self, interval_min):
        if interval_min < 1:
            interval_min = 1
        with self.lock:
            self.interval_min = interval_min

    def start(self):
        if self.scheduler_thread is None or not self.scheduler_thread.is_alive():
            self.stop_flag.clear()
            self.scheduler_thread = threading.Thread(target=self.scheduler_loop, daemon=True)
            self.scheduler_thread.start()

    def restart(self, interval_min):
        self.stop_flag.set()
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=2)
        self.set_interval(interval_min)
        self.start()


# 全局调度器
scheduler: TaskScheduler = None


# =================== FastAPI 应用 ===================
app = FastAPI(title="EdgeOne IPv6 动态源站")


@app.get("/")
async def index():
    return FileResponse(str(STATIC_PATH / "index.html"))


@app.get("/api/status")
async def api_status():
    return app_status


@app.get("/api/config")
async def api_get_config():
    return read_config()


@app.post("/api/config")
async def api_save_config(request: Request):
    global scheduler
    data = await request.json()
    if save_config(data):
        interval = data.get("IntervalMin", 15)
        if scheduler:
            scheduler.restart(int(interval))
        return {"message": "配置已保存"}
    return {"message": "保存失败"}


@app.get("/api/interfaces")
async def api_interfaces():
    return IPv6Tool.list_interfaces()


@app.post("/api/run")
async def api_run():
    threading.Thread(target=update_task, daemon=True).start()
    return {"message": "任务已触发"}


@app.get("/api/logs")
async def api_logs():
    if LOG_FILE.exists():
        try:
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()[-100:]
                return {"logs": "".join(lines)}
        except Exception:
            pass
    return {"logs": ""}


# 挂载静态文件
if STATIC_PATH.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_PATH)), name="static")


# =================== 主函数 ===================
def main():
    global scheduler

    parser = argparse.ArgumentParser(description="EdgeOne IPv6 动态源站更新")
    parser.add_argument('-p', '--port', type=int, default=54321, help='Web UI 端口 (默认: 54321)')
    parser.add_argument('--no-web', action='store_true', help='不启动Web界面，仅执行一次更新')
    args = parser.parse_args()

    if args.no_web:
        # 命令行模式：仅执行一次更新
        update_task()
    else:
        # Web模式：启动Web界面和定时任务
        config = read_config()
        interval = config.get("IntervalMin", 15)

        scheduler = TaskScheduler(interval_min=int(interval))
        scheduler.start()

        logger.info(f"Web界面启动在 http://0.0.0.0:{args.port}")
        uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()

