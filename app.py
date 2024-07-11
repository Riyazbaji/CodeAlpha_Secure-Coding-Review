from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', 'World')
    return render_template_string('<h1>Hello, {{ name }}</h1>')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    # For simplicity, let's assume the password is 'password123'
    if username == 'admin' and password == 'password123':
        return 'Login successful!'
    else:
        return 'Invalid credentials!', 401

if __name__ == '__main__':
    app.run(debug=True)
from flask import escape

@app.route('/')
def index():
    name = escape(request.args.get('name', 'World'))
    return render_template_string('<h1>Hello, {{ name }}</h1>')
from werkzeug.security import check_password_hash, generate_password_hash

# Example hash generation (run once and store securely)
password_hash = generate_password_hash('password123')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username == 'admin' and check_password_hash(password_hash, password):
        return 'Login successful!'
    else:
        return 'Invalid credentials!', 401
if __name__ == '__main__':
    app.run(debug=False)
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)
@app.route('/login', methods=['POST'])
def login():
    ...


