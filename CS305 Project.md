```python
def handle_client:
    while Ture:
        ....(the code to process request and send reponse back)
        when the Connection filed in header is Close:
            break the while outer loop
	close the socket between server and this client
```

```python
def start_server(self):
    while True:
        client_socket, addr = self.server_socket.accept()
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
        client_handler.start()
```

```python
# 发送加密请求获得服务器的公钥
url = 'http://127.0.0.1:8080/'
headers = {"Authorization": "Basic Y2xpZW50MToxMjM=", "isEncrypt": "1"}
r = requests.get(url=url, headers=headers)
pem_key = r.content
public_key_of_server = serialization.load_pem_public_key(
    pem_key,
    backend=default_backend()
)
# 生成自己的密钥
my_key = Fernet.generate_key()
cipher_suite = Fernet(my_key)
# 用服务器的公钥加密自己的密钥
encrypted_key = public_key_of_server.encrypt(
    my_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# 发送加密后的密钥
r = requests.post(url=url, headers=headers, data=encrypted_key)
```

