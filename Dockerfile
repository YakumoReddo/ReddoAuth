# 使用官方精简版 Python 基础镜像
FROM python:3.11-slim

# 设置环境变量，避免生成 .pyc，并让输出不被缓冲
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 工作目录
WORKDIR /app

# 先复制依赖文件并安装依赖（利用缓存层）
COPY requirements.txt /app/requirements.txt
COPY debian.sources /etc/apt/sources.list.d/debian.sources

# 更新 apt 索引并安装 pip 依赖所需的基本工具（如需编译扩展）
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && apt-get purge -y --auto-remove build-essential \
    && rm -rf /var/lib/apt/lists/*

# 复制项目代码
COPY . /app

# 暴露应用运行端口（容器内部）
EXPOSE 5000

# 使用 gunicorn 作为 WSGI 服务器来运行 Flask 应用（生产推荐）
# 假设入口 app.py 中创建的 Flask app 对象名为 app
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]