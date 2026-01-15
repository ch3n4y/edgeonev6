FROM python:3.11-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY main.py .
COPY static/ static/

# 暴露端口
EXPOSE 54321

# 启动命令
CMD ["python", "main.py", "-p", "54321"]
