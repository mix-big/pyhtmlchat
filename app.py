from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib # パスワードハッシュ化用 (本番環境では bcrypt や passlib を推奨)
import secrets # セッションキー生成用

app = Flask(__name__)
# セッションのセキュリティのための秘密鍵。本番環境では環境変数などから安全に取得すること。
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)

# データベースファイルのパス
DATABASE = 'site.db'

def get_db():
    """データベース接続を取得"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # カラム名でアクセスできるようにする
    return conn

def init_db():
    """データベースの初期化（テーブル作成）"""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        ''')
        db.commit()
        print("Database initialized.")

# アプリケーション起動時にデータベースを初期化
init_db()

@app.before_request
def make_session_permanent():
    """セッションを永続化（ブラウザを閉じても維持）"""
    session.permanent = True # デフォルトで永続化しないので設定

@app.route('/')
def home():
    """トップページ（ログイン状態によってリダイレクト）"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """ユーザー登録ページ"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            flash('全ての項目を入力してください。', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('パスワードと確認用パスワードが一致しません。', 'error')
            return render_template('register.html')

        # パスワードのハッシュ化 (本番環境では bcrypt などを使う)
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, password_hash))
            db.commit()
            flash('ユーザー登録が完了しました！ログインしてください。', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('そのユーザー名はすでに使用されています。', 'error')
        finally:
            db.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ログインページ"""
    if 'username' in session: # すでにログイン済みならダッシュボードへ
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('ユーザー名とパスワードを入力してください。', 'error')
            return render_template('login.html')

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone() # ユーザー情報を取得
        db.close()

        if user:
            # 入力されたパスワードをハッシュ化し、データベースのハッシュと比較
            input_password_hash = hashlib.sha256(password.encode()).hexdigest()
            if input_password_hash == user['password_hash']:
                session['username'] = user['username'] # セッションにユーザー名を保存
                flash(f'ようこそ、{user["username"]}さん！', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('ユーザー名またはパスワードが間違っています。', 'error')
        else:
            flash('ユーザー名またはパスワードが間違っています。', 'error')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """ログイン後のダッシュボードページ"""
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash('ログインしてください。', 'info')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """ログアウト処理"""
    session.pop('username', None) # セッションからユーザー名を削除
    flash('ログアウトしました。', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    # デバッグモードは開発用。本番環境では無効にする。
    # host='0.0.0.0' にすると、外部からのアクセスも可能になる。
    app.run(debug=True, host='0.0.0.0', port=5000)
