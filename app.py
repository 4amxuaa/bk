# app.py
# -*- coding: utf-8 -*-
"""
文章管理系统 - Flask 后端 + 前端托管
技术栈: Flask + flask-cors + PyJWT + sqlite3 (原生)
"""
import os
import sqlite3
import uuid
import hashlib
import hmac
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS

# ==================== 配置项 ====================
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
ACCESS_TOKEN_EXPIRE = 15          # 分钟
REFRESH_TOKEN_EXPIRE = 7          # 天
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB
DATABASE = os.environ.get('DATABASE_PATH', 'app.db')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# 根目录（app.py 所在目录），用于托管 index.html
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=None)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# 允许所有来源跨域（同源部署时其实用不上，但保留兼容性）
CORS(app, resources={r"/api/*": {"origins": "*"}})

# 确保上传目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ==================== 数据库工具 ====================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def query_db(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def execute_db(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    lastrowid = cur.lastrowid
    cur.close()
    return lastrowid


# ==================== 密码哈希 ====================
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return f"{salt.hex()}:{pwd_hash.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(':')
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


# ==================== 统一响应格式 ====================
def success(data=None, message='操作成功'):
    return jsonify({'code': 0, 'message': message, 'data': data})


def error(message, code=400):
    return jsonify({'code': code, 'message': message}), code


# ==================== Token 工具 ====================
def generate_access_token(user_id, username, role):
    now = datetime.utcnow()
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'type': 'access',
        'iat': now,
        'exp': now + timedelta(minutes=ACCESS_TOKEN_EXPIRE)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def generate_refresh_token(user_id):
    token = uuid.uuid4().hex + uuid.uuid4().hex
    expires_at = (datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE)).isoformat()
    execute_db(
        'INSERT INTO refresh_tokens (user_id, token, expires_at, revoked) VALUES (?, ?, ?, 0)',
        (user_id, token, expires_at)
    )
    return token


def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except Exception:
        return None


def get_token_from_header():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:].strip()
    return None


# ==================== 装饰器 ====================
def token_required(roles=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = get_token_from_header()
            if not token:
                return error('未提供认证令牌', 401)
            payload = decode_token(token)
            if not payload or payload.get('type') != 'access':
                return error('令牌无效或已过期', 401)
            if roles and payload.get('role') not in roles:
                return error('权限不足', 403)

            user = query_db('SELECT * FROM users WHERE id = ?', (payload['user_id'],), one=True)
            if not user:
                return error('用户不存在', 401)

            g.current_user = {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            }
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def optional_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        g.current_user = None
        token = get_token_from_header()
        if token:
            payload = decode_token(token)
            if payload and payload.get('type') == 'access':
                user = query_db('SELECT * FROM users WHERE id = ?', (payload['user_id'],), one=True)
                if user:
                    g.current_user = {
                        'id': user['id'],
                        'username': user['username'],
                        'role': user['role']
                    }
        return fn(*args, **kwargs)
    return wrapper


# ==================== 请求日志 ====================
@app.before_request
def log_request():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {request.method} {request.path} - {ip}")


# ==================== 全局错误处理 ====================
@app.errorhandler(404)
def not_found(e):
    # API 路径返回 JSON，其他路径交给前端路由（返回 index.html）
    if request.path.startswith('/api/'):
        return error('资源不存在', 404)
    return send_from_directory(BASE_DIR, 'index.html')


@app.errorhandler(413)
def request_entity_too_large(e):
    return error('上传文件过大（最大5MB）', 413)


@app.errorhandler(500)
def internal_error(e):
    return error('服务器内部错误', 500)


# ==================== 数据库初始化 ====================
def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')
    cur = db.cursor()

    cur.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(post_id, user_id),
            FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            parent_id INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (parent_id) REFERENCES comments(id) ON DELETE CASCADE
        );
    ''')

    # ---------- 初始化用户 ----------
    if cur.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        # 允许通过环境变量自定义初始密码
        admin_pwd = os.environ.get('ADMIN_INIT_PASSWORD', 'admin123')
        alice_pwd = os.environ.get('USER_INIT_PASSWORD', 'user123')
        admin_hash = hash_password(admin_pwd)
        alice_hash = hash_password(alice_pwd)
        cur.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                    ('admin', admin_hash, 'admin'))
        cur.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                    ('alice', alice_hash, 'user'))
        db.commit()
        print(f'[init_db] 创建初始用户 admin / alice')

    admin = cur.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
    alice = cur.execute('SELECT id FROM users WHERE username = ?', ('alice',)).fetchone()
    admin_id = admin['id']
    alice_id = alice['id']

    # ---------- 初始化文章 ----------
    if cur.execute('SELECT COUNT(*) FROM posts').fetchone()[0] == 0:
        posts = [
            ('欢迎使用文章管理系统', '这是系统的第一篇文章，欢迎体验！你可以浏览、点赞、评论，登录后还能发布自己的文章。', admin_id),
            ('游客也能自由浏览', '本系统支持游客模式，未登录用户也可以查看文章列表和详情，但点赞、评论、发布需要登录。', admin_id),
            ('alice 的第一篇文章', '大家好，我是 alice，这是我的第一篇文章，请多多关照！', alice_id),
            ('响应式布局设计分享', '本系统采用响应式设计：移动端底部 Tab 栏，平板双列，桌面侧边栏，超大屏居中。', alice_id),
            ('点赞与评论功能说明', '点赞是切换式的：已赞再点会取消。评论支持两级嵌套，可以回复别人的评论。', admin_id),
        ]
        for title, content, author_id in posts:
            cur.execute('INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)',
                        (title, content, author_id))
        db.commit()

    # ---------- 第一篇文章的点赞 ----------
    first_post = cur.execute('SELECT id FROM posts ORDER BY id LIMIT 1').fetchone()
    if first_post:
        pid = first_post['id']
        if cur.execute('SELECT COUNT(*) FROM likes WHERE post_id = ?', (pid,)).fetchone()[0] == 0:
            cur.execute('INSERT INTO likes (post_id, user_id) VALUES (?, ?)', (pid, admin_id))
            cur.execute('INSERT INTO likes (post_id, user_id) VALUES (?, ?)', (pid, alice_id))
            db.commit()

        if cur.execute('SELECT COUNT(*) FROM comments WHERE post_id = ?', (pid,)).fetchone()[0] == 0:
            cur.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
                        (pid, admin_id, '欢迎来到文章管理系统，希望大家喜欢！'))
            cur.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
                        (pid, alice_id, '界面很漂亮，功能也很实用～'))
            db.commit()

    cur.close()
    db.close()
    print('数据库初始化完成')


# ==================== 认证模块 ====================
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not (3 <= len(username) <= 20):
        return error('用户名长度需为3-20位')
    if len(password) < 6:
        return error('密码长度至少6位')

    existing = query_db('SELECT id FROM users WHERE username = ?', (username,), one=True)
    if existing:
        return error('用户名已存在')

    pwd_hash = hash_password(password)
    user_id = execute_db(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        (username, pwd_hash, 'user')
    )
    return success({'id': user_id, 'username': username}, '注册成功')


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user or not verify_password(password, user['password']):
        return error('用户名或密码错误', 401)

    access_token = generate_access_token(user['id'], user['username'], user['role'])
    refresh_token = generate_refresh_token(user['id'])

    return success({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    }, '登录成功')


@app.route('/api/auth/refresh', methods=['POST'])
def refresh():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get('refresh_token') or ''

    if not refresh_token:
        return error('缺少 refresh_token', 401)

    record = query_db(
        'SELECT * FROM refresh_tokens WHERE token = ? AND revoked = 0',
        (refresh_token,), one=True
    )
    if not record:
        return error('refresh_token 无效或已撤销', 401)

    try:
        expires_at = datetime.fromisoformat(record['expires_at'])
    except Exception:
        return error('refresh_token 格式错误', 401)

    if datetime.utcnow() > expires_at:
        return error('refresh_token 已过期', 401)

    user = query_db('SELECT * FROM users WHERE id = ?', (record['user_id'],), one=True)
    if not user:
        return error('用户不存在', 401)

    new_access = generate_access_token(user['id'], user['username'], user['role'])
    return success({'access_token': new_access}, '刷新成功')


@app.route('/api/auth/logout', methods=['POST'])
@token_required()
def logout():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get('refresh_token') or ''
    if refresh_token:
        execute_db('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?', (refresh_token,))
    return success(message='已退出登录')


@app.route('/api/auth/me', methods=['GET'])
@token_required()
def me():
    u = query_db('SELECT id, username, role, created_at FROM users WHERE id = ?',
                 (g.current_user['id'],), one=True)
    return success(dict(u))


# ==================== 文章模块 ====================
@app.route('/api/posts', methods=['GET'])
@optional_token
def list_posts():
    page = max(1, int(request.args.get('page', 1)))
    size = min(50, max(1, int(request.args.get('size', 10))))
    keyword = (request.args.get('keyword') or '').strip()

    offset = (page - 1) * size
    where = ''
    args = []
    if keyword:
        where = 'WHERE p.title LIKE ? OR p.content LIKE ?'
        like = f'%{keyword}%'
        args = [like, like]

    total = query_db(f'SELECT COUNT(*) AS c FROM posts p {where}', args, one=True)['c']

    sql = f'''
        SELECT p.id, p.title, p.content, p.author_id, p.created_at,
               u.username AS author_name,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
        FROM posts p
        JOIN users u ON u.id = p.author_id
        {where}
        ORDER BY p.created_at DESC, p.id DESC
        LIMIT ? OFFSET ?
    '''
    rows = query_db(sql, args + [size, offset])

    current_user = g.current_user
    posts = []
    for r in rows:
        liked = False
        if current_user:
            liked = query_db(
                'SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?',
                (r['id'], current_user['id']), one=True
            ) is not None
        can_delete = bool(current_user and (
            current_user['id'] == r['author_id'] or current_user['role'] == 'admin'
        ))
        posts.append({
            'id': r['id'],
            'title': r['title'],
            'content': r['content'][:120],
            'author_id': r['author_id'],
            'author_name': r['author_name'],
            'created_at': (r['created_at'] or '').replace('T', ' ')[:19],
            'like_count': r['like_count'],
            'comment_count': r['comment_count'],
            'liked': liked,
            'can_delete': can_delete
        })

    return success({
        'list': posts,
        'total': total,
        'page': page,
        'size': size,
        'is_guest': current_user is None
    })


@app.route('/api/posts/<int:post_id>', methods=['GET'])
@optional_token
def get_post(post_id):
    r = query_db('''
        SELECT p.id, p.title, p.content, p.author_id, p.created_at,
               u.username AS author_name,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
        FROM posts p
        JOIN users u ON u.id = p.author_id
        WHERE p.id = ?
    ''', (post_id,), one=True)

    if not r:
        return error('文章不存在', 404)

    current_user = g.current_user
    liked = False
    if current_user:
        liked = query_db(
            'SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?',
            (post_id, current_user['id']), one=True
        ) is not None
    can_delete = bool(current_user and (
        current_user['id'] == r['author_id'] or current_user['role'] == 'admin'
    ))

    return success({
        'id': r['id'],
        'title': r['title'],
        'content': r['content'],
        'author_id': r['author_id'],
        'author_name': r['author_name'],
        'created_at': (r['created_at'] or '').replace('T', ' ')[:19],
        'like_count': r['like_count'],
        'comment_count': r['comment_count'],
        'liked': liked,
        'can_delete': can_delete,
        'is_guest': current_user is None
    })


@app.route('/api/posts', methods=['POST'])
@token_required()
def create_post():
    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    content = (data.get('content') or '').strip()

    if not title:
        return error('标题不能为空')
    if len(title) > 200:
        return error('标题过长（最多200字）')
    if not content:
        return error('内容不能为空')

    post_id = execute_db(
        'INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)',
        (title, content, g.current_user['id'])
    )
    return success({'id': post_id}, '发布成功')


@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
@token_required()
def delete_post(post_id):
    post = query_db('SELECT * FROM posts WHERE id = ?', (post_id,), one=True)
    if not post:
        return error('文章不存在', 404)

    if g.current_user['id'] != post['author_id'] and g.current_user['role'] != 'admin':
        return error('无权删除该文章', 403)

    execute_db('DELETE FROM posts WHERE id = ?', (post_id,))
    return success(message='删除成功')


# ==================== 点赞模块 ====================
@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
@token_required()
def toggle_like(post_id):
    post = query_db('SELECT id FROM posts WHERE id = ?', (post_id,), one=True)
    if not post:
        return error('文章不存在', 404)

    existing = query_db(
        'SELECT id FROM likes WHERE post_id = ? AND user_id = ?',
        (post_id, g.current_user['id']), one=True
    )

    if existing:
        execute_db('DELETE FROM likes WHERE id = ?', (existing['id'],))
        liked = False
    else:
        execute_db(
            'INSERT INTO likes (post_id, user_id) VALUES (?, ?)',
            (post_id, g.current_user['id'])
        )
        liked = True

    count = query_db(
        'SELECT COUNT(*) AS c FROM likes WHERE post_id = ?', (post_id,), one=True
    )['c']

    return success({'liked': liked, 'like_count': count}, '点赞成功' if liked else '已取消点赞')


@app.route('/api/posts/<int:post_id>/likes', methods=['GET'])
@optional_token
def list_likes(post_id):
    rows = query_db('''
        SELECT u.id, u.username, u.role, l.created_at
        FROM likes l
        JOIN users u ON u.id = l.user_id
        WHERE l.post_id = ?
        ORDER BY l.created_at DESC
    ''', (post_id,))
    return success([dict(r) for r in rows])


# ==================== 评论模块 ====================
def build_comment_tree(rows, current_user):
    comment_map = {}
    roots = []

    for r in rows:
        item = {
            'id': r['id'],
            'post_id': r['post_id'],
            'user_id': r['user_id'],
            'username': r['username'],
            'role': r['role'],
            'content': r['content'],
            'parent_id': r['parent_id'],
            'created_at': (r['created_at'] or '').replace('T', ' ')[:19],
            'can_delete': bool(current_user and (
                current_user['id'] == r['user_id'] or current_user['role'] == 'admin'
            )),
            'replies': []
        }
        comment_map[r['id']] = item

    for r in rows:
        item = comment_map[r['id']]
        if r['parent_id'] and r['parent_id'] in comment_map:
            comment_map[r['parent_id']]['replies'].append(item)
        else:
            roots.append(item)

    roots.sort(key=lambda x: x['id'], reverse=True)
    return roots


@app.route('/api/posts/<int:post_id>/comments', methods=['GET'])
@optional_token
def list_comments(post_id):
    rows = query_db('''
        SELECT c.id, c.post_id, c.user_id, c.content, c.parent_id, c.created_at,
               u.username, u.role
        FROM comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.post_id = ?
        ORDER BY c.id ASC
    ''', (post_id,))

    tree = build_comment_tree(rows, g.current_user)
    total = len(rows)
    return success({'list': tree, 'total': total})


@app.route('/api/posts/<int:post_id>/comments', methods=['POST'])
@token_required()
def create_comment(post_id):
    post = query_db('SELECT id FROM posts WHERE id = ?', (post_id,), one=True)
    if not post:
        return error('文章不存在', 404)

    data = request.get_json(silent=True) or {}
    content = (data.get('content') or '').strip()
    parent_id = data.get('parent_id')

    if not content:
        return error('评论内容不能为空')
    if len(content) > 1000:
        return error('评论内容最多1000字')

    if parent_id:
        parent = query_db(
            'SELECT id, post_id FROM comments WHERE id = ?', (parent_id,), one=True
        )
        if not parent:
            return error('父评论不存在', 404)
        if parent['post_id'] != post_id:
            return error('父评论不属于该文章', 400)

    comment_id = execute_db(
        'INSERT INTO comments (post_id, user_id, content, parent_id) VALUES (?, ?, ?, ?)',
        (post_id, g.current_user['id'], content, parent_id if parent_id else None)
    )
    return success({'id': comment_id}, '评论成功')


@app.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@token_required()
def delete_comment(comment_id):
    comment = query_db('SELECT * FROM comments WHERE id = ?', (comment_id,), one=True)
    if not comment:
        return error('评论不存在', 404)

    if g.current_user['id'] != comment['user_id'] and g.current_user['role'] != 'admin':
        return error('无权删除该评论', 403)

    execute_db('DELETE FROM comments WHERE id = ?', (comment_id,))
    return success(message='删除成功')


# ==================== 管理员模块 ====================
@app.route('/api/admin/users', methods=['GET'])
@token_required(roles=['admin'])
def admin_users():
    rows = query_db('''
        SELECT u.id, u.username, u.role, u.created_at,
               (SELECT COUNT(*) FROM posts p WHERE p.author_id = u.id) AS post_count
        FROM users u
        ORDER BY u.id ASC
    ''')
    return success([dict(r) for r in rows])


@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@token_required(roles=['admin'])
def update_user_role(user_id):
    data = request.get_json(silent=True) or {}
    role = (data.get('role') or '').strip()

    if role not in ('user', 'admin'):
        return error('角色只能是 user 或 admin')

    user = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return error('用户不存在', 404)

    execute_db('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    return success(message='角色更新成功')


# ==================== 上传模块 ====================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/upload', methods=['POST'])
@token_required()
def upload_file():
    if 'file' not in request.files:
        return error('未选择文件')

    file = request.files['file']
    if not file or file.filename == '':
        return error('未选择文件')

    if not allowed_file(file.filename):
        return error('仅支持 png/jpg/jpeg/gif/webp 格式')

    ext = file.filename.rsplit('.', 1)[1].lower()
    new_name = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], new_name)
    file.save(filepath)

    return success({
        'filename': new_name,
        'url': f'/uploads/{new_name}'
    }, '上传成功')


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ==================== 公开模块 ====================
@app.route('/api/public/health', methods=['GET'])
def health():
    return success({
        'status': 'ok',
        'time': datetime.now().isoformat()
    }, '服务正常')


# ==================== 前端托管 ====================
@app.route('/')
def serve_index():
    """托管单文件前端"""
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    """
    兜底路由：
    - 若请求的是真实存在的静态文件（如 favicon.ico），直接返回
    - 否则一律返回 index.html，交给前端处理（SPA 回退）
    """
    # 安全：禁止路径穿越
    safe_path = os.path.normpath(filename)
    if safe_path.startswith('..') or os.path.isabs(safe_path):
        return error('非法路径', 400)

    full_path = os.path.join(BASE_DIR, safe_path)
    if os.path.isfile(full_path):
        return send_from_directory(BASE_DIR, safe_path)

    # 兜底返回 index.html（SPA 路由回退）
    return send_from_directory(BASE_DIR, 'index.html')

init_db()
# ==================== 启动 ====================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    app.run(debug=debug, host='0.0.0.0', port=port)