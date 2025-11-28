# 简单前置登录服务（Python + Flask）说明

说明：
- 该服务提供 auth 子请求检查、登录、登出、个人中心等功能，用于配合 nginx 的 auth_request 对静态站点进行登录保护。
- 配置中 cookie 的 domain 使用 `.example.com`，以便跨子域共享登录 cookie。请根据实际域名调整。

主要端点：
- GET /auth  - nginx 用于子请求鉴权，返回 200 表示允许访问，401 表示拒绝（nginx 可据此 redirect 到登录页）。
- GET /login - 登录页面（登录表单），支持 next 参数用于登录后跳回原始 URL。
- POST /login - 登录提交：参数 username, password_hash（MD5哈希）, remember (on/off), fingerprint（浏览器指纹）, next
- POST /logout - 注销当前 cookie（需要带 cookie）
- GET /account - 个人中心（需登录），显示当前用户的 token/ip/domain 列表，可点击删除 token。
- GET /add_user - 添加用户页面（仅管理员可用）
- POST /add_user - 添加新用户：参数 new_username, password_hash（MD5哈希）

安全特性：
- 密码在前端通过 MD5 哈希后传输，避免明文密码在网络中传输
- 浏览器指纹采集用于辅助身份验证
- 管理员用户可通过环境变量自动创建

环境变量：
- MYSQL_HOST - MySQL 主机地址
- MYSQL_PORT - MySQL 端口
- MYSQL_DATABASE - 数据库名
- MYSQL_USER - 数据库用户名
- MYSQL_PASSWORD - 数据库密码
- DEFAULT_ADMIN_PASSWORD - 默认管理员密码（首次启动时用于创建 admin 用户）

快速开始（示例）：
1. 安装依赖
   pip install -r requirements.txt

2. 配置数据库连接（在 app.py 的 SQLALCHEMY_DATABASE_URI 中修改为你的 MySQL 连接字符串）

3. 设置管理员密码
   export DEFAULT_ADMIN_PASSWORD=your_secure_password

4. 初始化数据库
   - 通过 db_init.sql 创建表，或用 SQLAlchemy 自动建表：
     python
     >>> from app import db
     >>> db.create_all()

   或使用提供的 db_init.sql。

5. 运行服务（生产建议用 gunicorn/uwsgi）
   FLASK_APP=app.py flask run --host=0.0.0.0 --port=5000

6. nginx 配置（示例片段见 nginx.conf）：
   - 在需要保护的 server（如 monitor.example.com）里使用 auth_request 指向 auth 服务。
   - 当 auth_request 返回 401 时，nginx 会 redirect 到 auth.example.com 的 /login，登录完成后再跳回原来的 URL。

安全和注意事项：
- 本示例适合作为 PoC，生产环境请：
  - 使用 HTTPS（cookie 设置 Secure）
  - 加强密码策略、输入校验、速率限制
  - 使用更严格的 fingerprint 验证逻辑
  - 保护登录接口以防暴力破解（如登录尝试限制、IP 黑名单）
  - 对 cookie 设置 SameSite、Secure、HttpOnly 并考虑签名或加密 token 内容