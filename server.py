import argparse
import base64
import socket
import threading
import os
import uuid
import time
import mimetypes
from jinja2 import Template

from http_request import HttpRequest

user_auth = {}
local_cookie = {}
cookie_time = {}
max_file_size = 1024 * 1024 * 10
chunk_size = 1024 * 1024


def my_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--host', type=str)
    parser.add_argument('-p', '--port', type=int)
    args = parser.parse_args()
    host = args.host
    port = args.port
    return host, port


def initial_user():
    user_auth['client1'] = '123'
    user_auth['client2'] = '123'
    user_auth['client3'] = '123'


class HttpServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
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
        with open('file_view.html', 'r') as f:
            content = f.read()
        html_template = Template(content)
        files = ''
        url_path = path.replace('tmp\\', '/')
        # print("path111", path)
        if path != 'tmp\\':
            parent_directory = os.path.abspath(os.path.join(url_path, os.pardir))[3:]
            # print("path222", parent_directory)
            files += '<li><a href="{}">/..</a></li>\n'.format("/" + parent_directory + "?SUSTech-HTTP=0")
        for file in os.listdir(path):
            file_list.append(file)
            file_path = os.path.join(path, file)
            url_path_1 = file_path.replace('tmp\\', '/')
            if os.path.isfile(file_path):
                files += '<li><a href="{}" download>{}</a></li><button onclick="deleteFile()">Delete</button>\n'.format(
                    url_path_1, file, url_path_1.replace('\\','/'))
            else:
                files += '<li><a href="{}">{}</a></li>\n'.format(url_path_1 + "?SUSTech-HTTP=0", file)
        html_content = html_template.render(files=files, path=url_path)
        return html_content, file_list

    def create_http_response(self, status_code, status_text, headers, body):
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        for key, value in headers.items():
            response += f"{key}: {value}\r\n"
        response += "\r\n"
        response += body
        return response

    def get_status(self, request, http_request):
        headers = request['headers']
        if request['path'].lower().startswith('/login'):
            return 410, 'login'
        # 前提：认证对应账号
        if 'Authorization' in headers:
            http_request.username, http_request.password = self.get_authorization(request, http_request)
            if http_request.username not in user_auth or user_auth[http_request.username] != http_request.password:
                return 401, 'Unauthorized'
            else:
                http_request.is_login = True
                return 200, 'OK'
        elif 'Cookie' in headers:
            # 判断本地是否有这个cookies
            cookies = headers['Cookie'].split('; ')
            header_cookie = ''
            for cookie in cookies:
                if cookie.startswith('session='):
                    header_cookie = cookie
                    for key, value in local_cookie.items():
                        if value == header_cookie:
                            http_request.username = key
            print("http_request.username", http_request.username)
            if http_request.username == '':
                return 408, 'Need login'
            if header_cookie in local_cookie:
                if local_cookie[http_request.username] == headers['Cookie']:
                    if time.time() - cookie_time[http_request.username] > 60:
                        return 401, 'Unauthorized'
                    else:
                        cookie_time[http_request.username] = time.time()
                        return 200, 'OK'
                else:
                    return 401, 'Unauthorized'
            else:
                # 第一次登录 但是这个cookie不是我们的server发送给浏览器的
                # local_cookie[http_request.username] = headers['Cookie']
                return 401, ''
        else:
            return 401, 'Unauthorized'
        return 200, 'OK'

    def get_file_type(self, path):
        mime_type, encoding = mimetypes.guess_type(path)
        return mime_type, encoding

    def get_headers(self, request, status_code, body, http_request):
        headers = {"Server": "CS305 Project"}
        if http_request.is_chunked:
            headers['Transfer-Encoding'] = 'chunked'
            headers['Content-Type'] = http_request.file_type
            headers['Last-Modified'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                                     time.gmtime(os.path.getmtime(http_request.file_path)))
        else:
            # Content-Type 可能不止 text
            if 'Range' in request['headers']:
                ranges = request['headers']['Range'].split(',')
                if len(ranges) != 1:
                    headers['Content-Type'] = 'multipart/byteranges; boundary=3d6b6a416f9b5'
                    headers['Content-Length'] = len(body.encode('utf-8'))
                    headers['Last-Modified'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                                             time.gmtime(os.path.getmtime(http_request.file_path)))
                else:
                    headers['Content-Type'] = http_request.file_type
                    headers['Content-Length'] = len(body.encode('utf-8'))
                    headers['Last-Modified'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                                             time.gmtime(os.path.getmtime(http_request.file_path)))
                    headers['Content-Range'] = 'bytes' + str(ranges[0]) + "/" + str(http_request.file_size)
                    http_request.file_size = 0
            else:
                if http_request.file_path != '':
                    headers['Content-Type'] = http_request.file_type
                    headers['Content-Length'] = len(body.encode('utf-8'))
                    headers['Last-Modified'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                                             time.gmtime(os.path.getmtime(http_request.file_path)))
                else:
                    headers['Content-Type'] = http_request.file_type
                    headers['Content-Length'] = len(body.encode('utf-8'))
        if 'Cookie' not in request['headers'] or http_request.is_login:
            rand = uuid.uuid4()
            headers['Set-Cookie'] = 'session=' + str(rand)
            local_cookie[http_request.username] = headers['Set-Cookie']
            print("local_cookie", local_cookie)
            cookie_time[http_request.username] = time.time()
            print("cookie_time", cookie_time)
        else:
            headers['Cookie'] = request['headers']['Cookie']
        headers['Connection'] = 'keep-alive'
        if status_code == 401:
            headers['WWW-Authenticate'] = 'Basic realm="Authorization Required"'
        headers['Date'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        return headers

    def get_body(self, status_code, request, http_request):
        if status_code == 410:
            with open('login.html', 'r') as f:
                return 200, f.read()
        # path = '/', 不需要 body
        if request['path'] == '/':
            return 200, ''
        # '?' 前判断是 GET方法的 view/download, 还是 POST 方法的 upload/delete
        path = request['path'].split('?')[0]
        # print('path:', path)
        paths = path.split("/")
        # 看起来 /upload /delete 和 POST 绑定
        if path == '/upload' or path == '/delete' or path == '/rename' or path == '/addDirectory':
            if status_code == 408:
                with open('login.html', 'r') as f:
                    return 408, f.read()
            if request['method'] != 'POST':
                return 405, "Method Not Allowed"
            parameter = request['path'].split('?')[1]
            post_paths = parameter.split('=')[1].split("/")
            post_user = ''
            for parts in post_paths:
                if parts != '':
                    post_user = parts
                    break
            if post_user != http_request.username:
                return 403, 'Forbidden'  # 没body的吧
            root_path = "tmp"
            root_path = os.path.join(root_path, post_user)
            # 还要加入 filename, body 还不会解析
            if path == '/upload':
                # upload 的文件夹是否存在
                if not os.path.exists(root_path):
                    return 404, 'Not Found'
                file_name, file_content = self.get_file(request)
                root_path = os.path.join(root_path, file_name)
                if not os.path.exists(root_path):
                    return 406, 'Already Exist'
                # print('root_path:', root_path)
                # print('file_content:', file_content)
                open(root_path, 'w').write(file_content)
                return 200, ''
            if path == '/addDirectory':
                if not os.path.exists(root_path):
                    return 404, 'Not Found'
                new_directory = request['path'].split('?')[2]
                directory_name = new_directory.split('=')[1]
                root_path = os.path.join(root_path, directory_name)
                if not os.path.exists(root_path):
                    return 406, 'Already Exist'
                os.mkdir(root_path)
                return 200, ''
            if path == '/delete':
                file_name = post_paths[-1]
                root_path = os.path.join(root_path, file_name)
                # delete 的文件是否存在
                if not os.path.isfile(root_path):
                    return 404, 'Not Found'
                os.remove(root_path)
                return 200, ''
            if path == '/rename':
                file_name = post_paths[-1]
                # delete 的文件是否存在
                if not os.path.isfile(os.path.join(root_path, file_name)):
                    return 404, 'Not Found'
                new_filename = request['path'].split('?')[2].split('=')[1]
                if not os.path.exists(os.path.join(root_path, new_filename)):
                    return 406, 'Already Exist'
                os.rename(os.path.join(root_path, file_name), os.path.join(root_path, new_filename))
                return 200, ''
        else:
            if request['method'] != 'GET':
                return 405, "Method Not Allowed"
            root_path = "tmp"
            for path in paths:
                root_path = os.path.join(root_path, path)
            if os.path.isfile(root_path):
                http_request.file_type, http_request.encoding = self.get_file_type(root_path)
                http_request.file_path = root_path
                http_request.file_size = os.path.getsize(root_path)
                if request['path'].split('?')[-1] == 'chunked=1' or http_request.file_size >= max_file_size:
                    # chunk transfer
                    http_request.is_chunked = True
                    return 200, root_path
                else:
                    # simple transfer
                    if 'Range' in request['headers']:
                        code1, body1 = self.breakpoint_transmission(request, root_path, http_request)
                        return code1, body1
                    # print(open(root_path, 'rb').read().decode('utf-8'))
                    return 200, open(root_path, 'rb').read().decode('utf-8')
            if not os.path.exists(root_path):
                return 404, 'Not Found'
            html, file_list = self.generate_html(root_path)
            if request['path'].split('?')[-1] == 'SUSTech-HTTP=0':
                http_request.file_type = 'text/html'
                return 200, html
            if request['path'].split('?')[-1] == 'SUSTech-HTTP=1':
                http_request.file_type = 'text/html'
                return 200, '[ "' + '", "'.join(file_list) + '"]'
            return 400, "Bad Request"

    def breakpoint_transmission(self, request, file_path, http_request):
        body = b''
        ranges = request['headers']['Range'].split(',')
        if len(ranges) == 1:
            # single range
            start, end = map(int, ranges[0].split('-'))
            if start >= end or end >= os.path.getsize(file_path):
                return 416, 'Range Not Satisfiable'
            http_request.file_size = os.path.getsize(file_path)
            with open(file_path, 'rb') as file:
                file.seek(start)
                body = file.read(end - start + 1)
        else:
            # multi range
            responses = []
            boundary = uuid.uuid4().hex
            for bk_range in ranges:
                start, end = map(int, bk_range.split('-'))
                if start >= end or end >= os.path.getsize(file_path):
                    return 416, 'Range Not Satisfiable'
                with open(file_path, 'rb') as file:
                    file.seek(start)
                    data = file.read(end - start + 1)
                    response = {
                        'Content-Type': http_request.file_type,
                        'Content-Range': f'bytes {start}-{end}/{os.path.getsize(file_path)}',
                        'body': data
                    }
                    responses.append(response)
            for resp in responses:
                body += f"--{boundary}\r\n".encode()
                body += f"{'Content-Type'}: {resp['Content-Type']}\r\n".encode()
                body += f"{'Content-Range'}: {resp['Content-Range']}\r\n".encode()
                body += b"\r\n"
                body += resp['body'] + b"\r\n"
            body += f"--{boundary}--\r\n".encode()

        return 206, body.decode('utf-8')

    def get_authorization(self, request, http_request):
        auth_header = request['headers']['Authorization']
        encoded_credentials = auth_header.split(' ')[1]  # 获取 Basic 后面的编码字符串
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        http_request.username, http_request.password = decoded_credentials.split(':')
        # print(f"Username: {self.username}, Password: {self.password}")
        return http_request.username, http_request.password

    def get_file(self, request):
        file_name = request['body'].split('; filename="')[1].split('"')[0]
        file_content = request['body'].split('"\r\n\r\n')[1].split('\r\n')[0]
        return file_name, file_content

    def handle_client(self, client_socket):
        while True:
            # try:
            request = self.parse_http_request(client_socket)
            if request['method'] is None:
                break
            http_request = HttpRequest()
            print("request", request)
            status_code, status_text = self.get_status(request, http_request)
            body = ''
            # if request['method'] == 'GET':
            code, body = self.get_body(status_code, request, http_request)
            if code == 406:
                status_code, status_text = 406, 'Already Exist'
            if code == 403:
                status_code, status_text = 403, 'Forbidden'
            if code == 404:
                status_code, status_text = 404, 'Not Found'
            if code == 405:
                status_code, status_text = 405, 'Method Not Allowed'
            if code == 400:
                status_code, status_text = 400, 'Bad Request'
            if code == 206:
                status_code, status_text = 206, 'Partial Content'
            if code == 200:
                status_code, status_text = 200, 'OK'
            headers = self.get_headers(request, status_code, body, http_request)
            if http_request.is_chunked:
                # send headers
                client_socket.sendall(
                    self.create_http_response(status_code=status_code, status_text=status_text, headers=headers,
                                              body="").encode())
                # send body by chunk( this body actually is a file path )
                with open(body, 'rb') as f:
                    while True:
                        data = f.read(chunk_size)
                        if not data:
                            break
                        client_socket.sendall(f"{len(data):X}\r\n".encode())
                        client_socket.sendall(data)
                        client_socket.sendall(b"\r\n")
                        if len(data) < chunk_size:
                            break
                    client_socket.sendall(b"0\r\n\r\n")
                    http_request.is_chunked = False
            else:
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
    initial_user()
    host, port = my_parser()
    http_server = HttpServer(host, port)
    http_server.start_server()
