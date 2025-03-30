import requests

#通过api获取ipv6公网地址
def getIPv6Address():
    text = requests.get('https://v6.ident.me').text
    return text

# -*- coding: utf-8 -*-
import hashlib
import hmac
import json
import time
from datetime import datetime
from http.client import HTTPSConnection

import tkinter as tk
from tkinter import messagebox


def show_result():
    token = entry_token.get()
    password = entry_password.get()
    domain = entry_domain.get()
    hostname = entry_hostname.get()
    record = entry_record.get()

    # 显示输入的信息
    result_message = f"id； {token}\nkey: {password}\n域名: {domain}\n主机名: {hostname}\nrecord id：{record}"
    messagebox.showinfo("输入结果", result_message)

    # 存储在变量中
    global stored_token, stored_password, stored_domain, stored_hostname,stored_record
    stored_token = token
    stored_password = password
    stored_domain = domain
    stored_hostname = hostname
    stored_record = record


# 创建主窗口
root = tk.Tk()
root.title("用户输入界面")
root.geometry("400x300")

# 标签和输入框
label_text = tk.Label(root, text="输入确认后关掉ui即可\nrecord_id需dnspod查询一次获取", font=("Arial", 16))
label_text.pack(pady=20)

frame_inputs = tk.Frame(root)
frame_inputs.pack(pady=10)

# Token 输入
label_token = tk.Label(frame_inputs, text="Token:")
label_token.grid(row=0, column=0, padx=10, pady=5)
entry_token = tk.Entry(frame_inputs, width=30)
entry_token.grid(row=0, column=1, padx=10, pady=5)

# 密码 输入
label_password = tk.Label(frame_inputs, text="密码:")
label_password.grid(row=1, column=0, padx=10, pady=5)
entry_password = tk.Entry(frame_inputs, width=30, show="*")
entry_password.grid(row=1, column=1, padx=10, pady=5)

# 域名 输入
label_domain = tk.Label(frame_inputs, text="域名:")
label_domain.grid(row=2, column=0, padx=10, pady=5)
entry_domain = tk.Entry(frame_inputs, width=30)
entry_domain.grid(row=2, column=1, padx=10, pady=5)

# 主机名 输入
label_hostname = tk.Label(frame_inputs, text="主机名:")
label_hostname.grid(row=3, column=0, padx=10, pady=5)
entry_hostname = tk.Entry(frame_inputs, width=30)
entry_hostname.grid(row=3, column=1, padx=10, pady=5)


# record_id输入
label_record = tk.Label(frame_inputs, text="record_id:")
label_record.grid(row=3, column=0, padx=10, pady=5)
entry_record = tk.Entry(frame_inputs, width=30)
entry_record.grid(row=3, column=1, padx=10, pady=5)

# 提交按钮
button_submit = tk.Button(root, text="提交", command=show_result)
button_submit.pack(pady=20)

# 全局变量用于存储输入值
stored_token = ""
stored_password = ""
stored_domain = ""
stored_hostname = ""
stored_record = ""
# 运行应用
root.mainloop()

print(stored_token,stored_password,stored_domain,stored_hostname)
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


secret_id = stored_token
secret_key = stored_password
record_id = stored_record
token = ""

service = "dnspod"
host = "dnspod.tencentcloudapi.com"
region = ""
version = "2021-03-23"
action = "ModifyRecord"
# 定义IPv6地址变量
ipv6_address = getIPv6Address()

# 构建payload字符串
payload = f"""{{
  "Domain": "chaoxi.asia",
  "RecordType": "AAAA",
  "RecordLine": "默认",
  "Value": "{ipv6_address}",
  "RecordId": {record_id},
  "SubDomain": "ipv6",
  "TTL": 600
}}"""

print(payload)

params = json.loads(payload)
endpoint = "https://dnspod.tencentcloudapi.com"
algorithm = "TC3-HMAC-SHA256"
timestamp = int(time.time())
date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")

# ************* 步骤 1：拼接规范请求串 *************
http_request_method = "POST"
canonical_uri = "/"
canonical_querystring = ""
ct = "application/json; charset=utf-8"
canonical_headers = "content-type:%s\nhost:%s\nx-tc-action:%s\n" % (ct, host, action.lower())
signed_headers = "content-type;host;x-tc-action"
hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
canonical_request = (http_request_method + "\n" +
                     canonical_uri + "\n" +
                     canonical_querystring + "\n" +
                     canonical_headers + "\n" +
                     signed_headers + "\n" +
                     hashed_request_payload)

# ************* 步骤 2：拼接待签名字符串 *************
credential_scope = date + "/" + service + "/" + "tc3_request"
hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
string_to_sign = (algorithm + "\n" +
                  str(timestamp) + "\n" +
                  credential_scope + "\n" +
                  hashed_canonical_request)

# ************* 步骤 3：计算签名 *************
secret_date = sign(("TC3" + secret_key).encode("utf-8"), date)
secret_service = sign(secret_date, service)
secret_signing = sign(secret_service, "tc3_request")
signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

# ************* 步骤 4：拼接 Authorization *************
authorization = (algorithm + " " +
                 "Credential=" + secret_id + "/" + credential_scope + ", " +
                 "SignedHeaders=" + signed_headers + ", " +
                 "Signature=" + signature)

# ************* 步骤 5：构造并发起请求 *************
headers = {
    "Authorization": authorization,
    "Content-Type": "application/json; charset=utf-8",
    "Host": host,
    "X-TC-Action": action,
    "X-TC-Timestamp": timestamp,
    "X-TC-Version": version
}
if region:
    headers["X-TC-Region"] = region
if token:
    headers["X-TC-Token"] = token
while(1):

    try:
        req = HTTPSConnection(host)
        req.request("POST", "/", headers=headers, body=payload.encode("utf-8"))
        resp = req.getresponse()
        print(resp.read())
    except Exception as err:
        print(err)

    time.sleep(3600)
