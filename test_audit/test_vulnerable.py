#!/usr/bin/env python3
# 测试漏洞代码文件

import os
import subprocess
import pickle
import yaml

# 1. 命令注入漏洞
def vulnerable_command(user_input):
    # 危险：直接将用户输入拼接到命令中
    os.system(f"echo {user_input}")

# 2. 不安全的反序列化
def unsafe_deserialize(data):
    # 危险：直接反序列化不可信数据
    return pickle.loads(data)

# 3. SQL注入（模拟）
def vulnerable_sql(username):
    # 危险：直接将用户输入拼接到SQL查询中
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return query

# 4. 硬编码凭证
API_KEY = "supersecretapikey123"
PASSWORD = "admin123"

# 5. 不安全的文件处理
def unsafe_file_read(filename):
    # 危险：路径遍历漏洞
    with open(f"/tmp/{filename}", "r") as f:
        return f.read()

# 6. 密码硬编码在配置中
config = {
    "database": {
        "user": "admin",
        "password": "hardcodedpass123"
    }
}

# 7. 使用不安全的哈希算法
import hashlib
def unsafe_hash(password):
    # 危险：使用不安全的MD5算法
    return hashlib.md5(password.encode()).hexdigest()

# 8. 不安全的YAML加载
def unsafe_yaml_load(data):
    # 危险：使用yaml.load()而不是yaml.safe_load()
    return yaml.load(data)
