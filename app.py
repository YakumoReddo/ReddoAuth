# 主服务实现：Flask + SQLAlchemy
# 说明：将数据库连接字符串替换为你自己的 MySQL 配置

from datetime import datetime, timedelta
import secrets
import json
import os

from flask import Flask, request, make_response, redirect, render_template, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from utils import verify_fingerprint  # 指纹校验的占位函数

app = Flask(__name__)
# 从环境变量读取数据库连接信息，提供默认值以便本地开发
db_user = os.getenv('MYSQL_USER', 'authuser')
db_pass = os.getenv('MYSQL_PASSWORD', 'authpass')
db_host = os.getenv('MYSQL_HOST', '127.0.0.1')
db_port = os.getenv('MYSQL_PORT', '3306')
db_name = os.getenv('MYSQL_DATABASE', 'authdb')

# 构建 SQLALCHEMY 的连接字符串
# 注意：使用 pymysql 驱动（requirements.txt 中应有 PyMySQL）
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}?charset=utf8mb4"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 导入模型（放在本文件后面或单独 models.py）
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Token(db.Model):
    __tablename__ = 'tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    ip = db.Column(db.String(64), nullable=False)
    fingerprint = db.Column(db.Text, nullable=True)
    remember = db.Column(db.Boolean, default=False, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

db.create_all()  # 创建数据库表（如果不存在）
# 常量配置
COOKIE_NAME = 'access_token'
COOKIE_DOMAIN = '.example.com'  # 请根据实际调整
REMEMBER_DAYS = 30
SESSION_HOURS = 2

def create_token(user_id, domain, ip, remember=False, fingerprint=None):
    """创建 token 并保存到数据库"""
    token_str = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    if remember:
        expires = now + timedelta(days=REMEMBER_DAYS)
    else:
        expires = now + timedelta(hours=SESSION_HOURS)
    t = Token(
        user_id=user_id,
        token=token_str,
        domain=domain,
        ip=ip,
        fingerprint=fingerprint,
        remember=remember,
        expires_at=expires
    )
    db.session.add(t)
    db.session.commit()
    return t

def refresh_token(token_obj):
    """刷新 token 的有效期（基于是否记住登录）"""
    now = datetime.utcnow()
    if token_obj.remember:
        token_obj.expires_at = now + timedelta(days=REMEMBER_DAYS)
    else:
        token_obj.expires_at = now + timedelta(hours=SESSION_HOURS)
    db.session.commit()

def find_valid_token(token_str, domain, ip, fingerprint_json=None):
    """根据 token 字符串、域名、ip 和（可选）指纹查找是否有效"""
    if not token_str:
        return None, 'no_token'
    t = Token.query.filter_by(token=token_str, domain=domain).first()
    if not t:
        return None, 'no_such_token'
    now = datetime.utcnow()
    if t.expires_at < now:
        return None, 'expired'
    if t.ip == ip:
        return t, 'ok'
    # ip 不匹配，尝试指纹（当前为 stub：默认不通过）
    if t.fingerprint and fingerprint_json:
        try:
            stored_fp = json.loads(t.fingerprint)
            provided_fp = json.loads(fingerprint_json)
            if verify_fingerprint(stored_fp, provided_fp):
                return t, 'ok_by_fingerprint'
        except Exception:
            pass
    return None, 'ip_mismatch'

@app.route('/auth', methods=['GET', 'POST'])
def auth_request_check():
    """
    nginx 的 auth_request 会发起一个子请求到这里。
    - 检查请求 Cookie 中是否存在合法的 token（同 domain）
    - 如果合法返回 200
    - 否则返回 401
    nginx 可以在 401 情况下 redirect 到登录页并带上原始 url（如 X-Original-URI）
    """
    # nginx 在 proxy_set_header 中已把 Host, X-Real-IP, X-Original-URI, Cookie 等传过来
    host = request.headers.get('Host') or request.host
    ip = request.headers.get('X-Real-IP') or request.remote_addr
    fingerprint_json = request.headers.get('X-Fingerprint') or None  # 预留前端传指纹位置
    token_cookie = request.cookies.get(COOKIE_NAME)

    token_obj, reason = find_valid_token(token_cookie, host, ip, fingerprint_json)
    if token_obj:
        # 刷新 token 有效期
        refresh_token(token_obj)
        # 同时返回 Set-Cookie 续期（让浏览器保持）
        resp = make_response('', 200)
        resp.set_cookie(
            COOKIE_NAME, token_obj.token,
            domain=COOKIE_DOMAIN,
            httponly=True,
            secure=False,  # 生产请设为 True
            samesite='Lax',
            path='/'
        )
        return resp
    else:
        # 未通过验证
        # 返回 401，nginx 会据此 redirect 到登录页（参见 nginx.conf）
        return ('Unauthorized', 401)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    登录页：
    - GET: 展示登录表单（accepts ?next=）
    - POST: 校验用户名密码，创建 token，设置 cookie 并跳回 next
    """
    if request.method == 'GET':
        next_url = request.args.get('next', '/')
        return render_template('login.html', next=next_url)
    # POST 处理
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    remember = request.form.get('remember', '') == 'on'
    next_url = request.form.get('next') or '/'

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return render_template('login.html', error='用户名或密码错误', next=next_url)

    # 创建 token，绑定当前登录时的 ip 和 domain（domain 由请求 Host 决定）
    host = request.headers.get('Host') or request.host
    ip = request.headers.get('X-Real-IP') or request.remote_addr
    # 指纹从表单或 header 中获取（预留）
    fingerprint_json = request.form.get('fingerprint') or request.headers.get('X-Fingerprint')
    t = create_token(user.id, host, ip, remember=remember, fingerprint=fingerprint_json)

    resp = make_response(redirect(next_url))
    # 设置跨子域 cookie
    resp.set_cookie(
        COOKIE_NAME, t.token,
        domain=COOKIE_DOMAIN,
        httponly=True,
        secure=False,  # 生产请设为 True
        samesite='Lax',
        path='/'
    )
    return resp

@app.route('/logout', methods=['POST'])
def logout():
    """注销当前 cookie 对应的 token（仅删除与当前 token 匹配的记录）"""
    token_cookie = request.cookies.get(COOKIE_NAME)
    if token_cookie:
        t = Token.query.filter_by(token=token_cookie).first()
        if t:
            db.session.delete(t)
            db.session.commit()
    resp = make_response(redirect('/login'))
    resp.delete_cookie(COOKIE_NAME, domain=COOKIE_DOMAIN, path='/')
    return resp

def login_required_view(func):
    """简单的视图装饰器用于保护需要登录的页面（基于 token）"""
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        token_cookie = request.cookies.get(COOKIE_NAME)
        host = request.headers.get('Host') or request.host
        ip = request.headers.get('X-Real-IP') or request.remote_addr
        t, reason = find_valid_token(token_cookie, host, ip, request.headers.get('X-Fingerprint'))
        if not t:
            return redirect(url_for('login', next=request.url))
        # 刷新 token
        refresh_token(t)
        # 将当前 token 对象注入 request 以便视图使用
        request.current_token = t
        request.current_user = User.query.get(t.user_id)
        return func(*args, **kwargs)
    return wrapper

@app.route('/account', methods=['GET', 'POST'])
@login_required_view
def account():
    """
    个人中心：列出当前用户在不同域名下的 token/ip 信息，可删除指定 token（POST action=delete token_id）
    """
    user = request.current_user
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            token_id = request.form.get('token_id')
            t = Token.query.filter_by(id=token_id, user_id=user.id).first()
            if t:
                db.session.delete(t)
                db.session.commit()
    tokens = Token.query.filter_by(user_id=user.id).order_by(Token.created_at.desc()).all()
    # 把 fingerprint 字符串长度限制显示
    for tk in tokens:
        if tk.fingerprint and len(tk.fingerprint) > 200:
            tk._short_fp = tk.fingerprint[:200] + '...'
        else:
            tk._short_fp = tk.fingerprint
    return render_template('account.html', user=user, tokens=tokens)

# 供快速创建测试用户的接口（仅用于演示，生产请移除或保护）
@app.route('/_create_user', methods=['POST'])
def create_user_route():
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'user exists'}), 400
    u = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(u)
    db.session.commit()
    return jsonify({'ok': True, 'user_id': u.id})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)