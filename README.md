# EdgeOne IPv6 动态源站

EdgeOne 是腾讯云的边缘安全加速平台。本工具为其提供动态更新加速域名源站 IP 的功能。

适用于拥有动态 IPv6 地址的服务器，确保 EdgeOne 始终能够正确获取最新的源站地址。

## 功能特性

- 自动获取本机公网 IPv6 地址
- 支持多个加速域名同时更新
- Web 管理界面，配置简单
- 定时自动更新（可配置间隔）
- 可选 IPv6 公网可达性检测
- Docker 一键部署

## 快速开始

### Docker 部署（推荐）

```bash
# 创建配置文件（首次运行）
touch ~/.edgeonev6.config.yaml

# 使用 Docker Compose
wget https://raw.githubusercontent.com/ch3n4y/edgeonev6/main/docker-compose.yml
docker-compose up -d
```

或者手动运行：

```bash
docker run -d \
  --name edgeonev6 \
  --network=host \
  --restart=unless-stopped \
  -v ~/.edgeonev6.config.yaml:/root/.edgeonev6.config.yaml \
  ghcr.io/ch3n4y/edgeonev6:latest
```

启动后访问 `http://localhost:54321` 进行配置。

### 本地运行

```bash
# 安装依赖
pip install -r requirements.txt

# 启动 Web 界面
python main.py

# 指定端口
python main.py -p 8080

# 仅执行一次更新（不启动 Web）
python main.py --no-web
```

## 配置说明

通过 Web 界面配置以下内容：

| 配置项 | 说明 |
|--------|------|
| SecretId | 腾讯云 API 密钥 ID |
| SecretKey | 腾讯云 API 密钥 Key |
| 加速域名 | EdgeOne 站点 ID 和加速域名（支持多个） |
| 网卡 | 指定获取 IPv6 的网卡（可选） |
| 更新间隔 | 自动更新间隔时间（分钟） |
| IPv6 可达性检测 | 是否验证 IPv6 公网可达 |

### 获取腾讯云密钥

1. 登录 [腾讯云控制台](https://console.cloud.tencent.com/cam/capi)
2. 创建或查看 API 密钥
3. 建议使用子账号并仅授予 EdgeOne 相关权限

### 获取 EdgeOne 站点 ID

1. 登录 [EdgeOne 控制台](https://console.cloud.tencent.com/edgeone)
2. 进入站点管理，查看站点 ID（格式：`zone-xxxxxxxxx`）

## 截图

Web 管理界面：

- 实时显示当前 IPv6 地址
- 每个域名的更新状态
- 运行日志查看

## 注意事项

- Docker 需使用 `--network=host` 模式以获取宿主机真实 IPv6 地址
- 确保服务器已分配公网 IPv6 地址
- EdgeOne 加速域名需已添加到站点

## License

MIT
