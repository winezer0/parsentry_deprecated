# 包含多种常见漏洞的示例代码

import sqlite3
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

# 1. SQL注入漏洞示例
def sql_injection_example(user_id):
    """存在SQL注入漏洞的函数"""
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # 漏洞：直接拼接SQL查询，允许SQL注入
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

# 2. 命令注入漏洞示例
def command_injection_example(filename):
    """存在命令注入漏洞的函数"""
    # 漏洞：直接将用户输入传递给os.system
    os.system(f"cat {filename}")

# 3. XSS漏洞示例
@app.route('/xss')
def xss_example():
    """存在XSS漏洞的Flask路由"""
    name = request.args.get('name', 'Guest')
    # 漏洞：直接将用户输入渲染到HTML中，允许XSS攻击
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

# 4. 不安全的密码存储
def insecure_password_storage(password):
    """不安全的密码存储方式"""
    # 漏洞：明文存储密码，没有进行哈希处理
    with open('passwords.txt', 'a') as f:
        f.write(f"password: {password}\n")

# 5. 硬编码密钥
def hardcoded_key():
    """硬编码密钥的示例"""
    # 漏洞：硬编码的密钥可以被攻击者获取
    secret_key = "my_super_secret_key_12345"
    return secret_key

# 6. 不安全的文件上传
def insecure_file_upload(file_content, filename):
    """不安全的文件上传处理"""
    # 漏洞：没有验证文件类型，允许上传恶意文件
    with open(f"uploads/{filename}", 'wb') as f:
        f.write(file_content)

if __name__ == "__main__":
    app.run(debug=True)
