import argparse
import base64
import socket
import threading
import os
import uuid
import pathlib

user_auth = {}
local_cookies = {}


def my_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--host', type=str)
    parser.add_argument('-p', '--port', type=int)
    args = parser.parse_args()
    host = args.host
    port = args.port
    return host, port


class HttpServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.username = ''
        self.password = ''
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        # 设置最大连接数
        self.server_socket.listen(7)

    def start_server(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()

    def parse_http_request(self, sock):
        data = ""
        while True:
            chunk = sock.recv(1).decode()
            data += chunk
            if data.endswith("\r\n\r\n"):
                break
        lines = data.split("\r\n")
        method, path, version = lines[0].split(" ")
        headers = {}
        for line in lines[1:]:
            if line:
                key, value = line.split(": ", 1)
                headers[key] = value
        body = ""
        if "Content-Length" in headers:
            length = int(headers["Content-Length"])
            body = sock.recv(length).decode()
        return {"method": method, "path": path, "version": version, "headers": headers, "body": body}

    def generate_html(self, path):
        file_list = []
        html = f'<html>\n<h1>Directory listing for/{path}</h1>\n<body>\n<ul>\n'
        for file in os.listdir(path):
            file_list.append(file)
            file_path = os.path.join(path, file)
            html += '<li><a href="{}">{}</a></li>\n'.format(file_path, file)
        html += '</ul>\n</body>\n</html>'
        return html, file_list

    def create_http_response(self, status_code, status_text, headers, body):
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        for key, value in headers.items():
            response += f"{key}: {value}\r\n"
        response += "\r\n"
        response += body
        return response

    def get_status(self, request):
        status_code, status_text = 200, 'OK'
        headers = request['headers']
        body = request['body']
        if 'Authorization' in headers:
            username, password = self.get_authorization(request)
            if username in user_auth and user_auth[username] == password:
                status_code, status_text = 200, 'OK'
            else:
                status_code, status_text = 401, 'Unauthorized'
        else:
            status_code, status_text = 401, 'Unauthorized'
        return status_code, status_text

    def get_headers(self, request, status_code, body):
        headers = {"Content-Type": "text/html", "Content-Length": len(body.encode('utf-8'))}
        if 'Cookie' not in request['headers']:
            rand = uuid.uuid4()
            headers['Set-Cookie'] = 'session=' + str(rand)
            local_cookies[self.username] = headers['Set-Cookie']
        else:
            headers['Cookie'] = request['headers']['Cookie']
        headers['Connection'] = 'keep-alive'
        if status_code == 401:
            headers['WWW-Authenticate'] = 'Basic realm="Authorization Required"'
        return headers

    def get_body(self, request):
        if request['path'] == '/':
            return 200, ''
        if request['method'] != 'GET' and request['path'] != '/':
            return 405, "Method Not Allowed"
        root_path = "data"
        path = request['path'].split('?')[0]
        paths = path.split("/")
        for path in paths:
            root_path = os.path.join(root_path, path)
        if os.path.isfile(root_path):
            print(open(root_path, 'rb').read().decode('utf-8'))
            return 200, open(root_path, 'rb').read().decode('utf-8')
        if not os.path.exists(root_path):
            return 404, 'Not Found'
        html, file_list = self.generate_html(root_path)
        if request['path'].split('?')[-1] == 'SUSTech-HTTP=0':
            return 200, html
        if request['path'].split('?')[-1] == 'SUSTech-HTTP=1':
            return 200, '[ "' + '", "'.join(file_list) + '"]'
        return 400, "Bad Request"

    def get_authorization(self, request):
        auth_header = request['headers']['Authorization']
        encoded_credentials = auth_header.split(' ')[1]  # 获取 Basic 后面的编码字符串
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        self.username, self.password = decoded_credentials.split(':')
        # print(f"Username: {self.username}, Password: {self.password}")
        return self.username, self.password

    def handle_client(self, client_socket):
        while True:
            # try:
            request = self.parse_http_request(client_socket)
            if request['method'] is None:
                break
            print("request", request)
            status_code, status_text = self.get_status(request)
            body = ''
            # if request['method'] == 'GET':
            code, body = self.get_body(request)
            if code == 404:
                status_code, status_text = 404, 'Not Found'
            if code == 405:
                status_code, status_text = 405, 'Method Not Allowed'
            if code == 400:
                status_code, status_text = 400, 'Bad Request'
            headers = self.get_headers(request, status_code, body)
            response = self.create_http_response(status_code=status_code, status_text=status_text,
                                                 headers=headers, body=body)
            print("response", response)
            client_socket.sendall(response.encode())
            if request['headers'].get('Connection').lower() == 'close':
                break
            # except Exception as e:
            #     print(f"Error handling request: {e}")
            #     break
        client_socket.close()


if __name__ == '__main__':
    # 用户认证
    user_auth['client1'] = '123'
    host, port = my_parser()
    http_server = HttpServer(host, port)
    http_server.start_server()
