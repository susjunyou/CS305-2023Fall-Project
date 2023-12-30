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
chunk_size = 1024 * 1024 * 1
cookie_time_out = 3600


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
        print("CS305 HTTP Server is running...")
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
        body = b""
        if "Content-Length" in headers:
            length = int(headers["Content-Length"])
            while len(body) < length:
                body += sock.recv(min(length - len(body), chunk_size * 10))

        return {"method": method, "path": path, "version": version, "headers": headers, "body": body}

    def generate_html(self, path):
        file_list = []
        with open('file_view.html', 'r') as f:
            content = f.read()
        html_template = Template(content)
        files = ''
        url_path = path.replace('data\\', '/')
        # print("path111", path)
        if path != 'da\\':
            parent_directory = os.path.abspath(os.path.join(url_path, os.pardir))[3:]
            # print("path222", parent_directory)
            files += '<li class="file-item">' \
                     '<a href="{}" class="file-link">/..</a>' \
                     '</li>\n'.format("/" + parent_directory + "?SUSTech-HTTP=0")
        index = 0
        for file in os.listdir(path):
            file_list.append(file)
            file_path = os.path.join(path, file)
            url_path_1 = file_path.replace('data\\', '/')
            if os.path.isfile(file_path):
                files += '<li class="file-item">' \
                         '<a href="{}" class="file-link" download>{}</a>' \
                         '<div>' \
                         '<label for="new name"></label>' \
                         '<input type="text" id="newName{}" placeholder="newName" required style="margin-right:20px">' \
                         '<button class="delete-btn" onclick="renameFile({},{})" style="margin-right:10px">Rename</button>' \
                         '<button class="delete-btn" onclick="deleteFile({})">Delete</button>' \
                         '</div>' \
                         '</li>\n'.format(
                    url_path_1, file, str(index), "'" + url_path_1.replace('\\', '/') + "'", str(index),
                                                  "'" + url_path_1.replace('\\', '/') + "'")

            else:
                files += '<li class="file-item">' \
                         '<a href="{}" class="file-link">{}</a>' \
                         '<div>' \
                         '<label for="new name"></label>' \
                         '<input type="text" id="newName{}" placeholder="newName" required style="margin-right:20px">' \
                         '<button class="delete-btn" onclick="renameFile({},{})" style="margin-right:10px">Rename</button>' \
                         '<button class="delete-btn" onclick="deleteDir({})">Delete</button>' \
                         '</div>' \
                         '</li>\n'.format(url_path_1 + "?SUSTech-HTTP=0", '/' + file, str(index),
                                          "'" + url_path_1.replace('\\', '/') + "'", str(index),
                                          "'" + url_path_1.replace('\\', '/') + "'")
            index = index + 1
        html_content = html_template.render(files=files, path=url_path.replace('\\', '/'))
        return html_content, file_list

    def create_http_response(self, status_code, status_text, headers, body):
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        for key, value in headers.items():
            response += f"{key}: {value}\r\n"
        response += "\r\n"
        response = response.encode('utf-8')
        # print("errrrrrrrrrrr",response)
        # print(body)
        # response += body
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
                if cookie.startswith('session-id='):
                    header_cookie = cookie
                    for key, value in local_cookie.items():
                        if value == header_cookie:
                            http_request.username = key
            if http_request.username == '':
                return 401, 'Unauthorized'
            print("http_request.username", http_request.username)
            if http_request.username == '':
                return 408, 'Need login'
            else:
                if time.time() - cookie_time[http_request.username] > cookie_time_out:
                    return 401, 'Unauthorized'
                else:
                    cookie_time[http_request.username] = time.time()
                    return 200, 'OK'
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
        elif http_request.is_large_file:
            headers['Content-Length'] = os.path.getsize(http_request.file_path)
            headers['Content-Type'] = http_request.file_type
            headers['Last-Modified'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                                     time.gmtime(os.path.getmtime(http_request.file_path)))
        else:
            # Content-Type 可能不止 text
            if 'Range' in request['headers']:
                ranges = request['headers']['Range'].split(',')
                if len(ranges) != 1:
                    headers['Content-Type'] = 'multipart/byteranges; boundary=3d6b6a416f9b5'
                    headers['Content-Length'] = len(body)
                    headers['Last-Modified'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                                             time.gmtime(os.path.getmtime(http_request.file_path)))
                else:
                    headers['Content-Type'] = http_request.file_type
                    headers['Content-Length'] = len(body)
                    headers['Last-Modified'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                                             time.gmtime(os.path.getmtime(http_request.file_path)))
                    indexs = ranges[0].replace('bytes=', '').split('-')
                    start = int(indexs[0])
                    end = int(indexs[1]) if indexs[1] != '' else os.path.getsize(http_request.file_path) - 1

                    headers['Content-Range'] = 'bytes ' + str(start) + "-" + str(end) + "/" + str(http_request.file_size)
                    http_request.file_size = 0
            else:
                if http_request.file_path != '':
                    headers['Content-Type'] = http_request.file_type
                    headers['Content-Length'] = len(body)
                    headers['Last-Modified'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                                             time.gmtime(os.path.getmtime(http_request.file_path)))
                else:
                    headers['Content-Type'] = http_request.file_type
                    headers['Content-Length'] = len(body)
        if 'Cookie' not in request['headers'] or http_request.is_login:
            rand = uuid.uuid4()
            headers['Set-Cookie'] = 'session-id=' + str(rand)
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

    def decode_url(self, s):
        parts = s.split('%')
        result = [parts[0]]
        for part in parts[1:]:
            i = int(part[:2], 16)
            result.append(chr(i) + part[2:])
        return ''.join(result)

    def get_body(self, status_code, request, http_request):
        if request['method'] == 'HEAD':
            return 200, ''.encode('utf-8')
        if status_code == 410 or status_code == 401:
            with open('login.html', 'r') as f:
                return 410, f.read().encode('utf-8')

        # '?' 前判断是 GET方法的 view/download, 还是 POST 方法的 upload/delete
        path = request['path'].split('?')[0]
        print('path:-----------------', path)
        paths = path.split("/")
        if path == '/check':
            return 200, ''.encode('utf-8')
        if request['method'] == 'DELE':
            root_path = "data"
            for part in paths:
                root_path = os.path.join(root_path, part)
            if os.path.exists(root_path):
                if os.path.isdir(root_path):
                    os.rmdir(root_path)
                    return 200, ''.encode('utf-8')
                elif os.path.isfile(root_path):
                    os.remove(root_path)
                    return 200, ''.encode('utf-8')
            return 404, ''.encode('utf-8')
        # 看起来 /upload /delete 和 POST 绑定
        if path == '/upload' or path == '/delete' or path == '/rename' or path == '/addDirectory':
            if status_code == 408:
                with open('login.html', 'r') as f:
                    return 408, f.read().encode('utf-8')
            if request['method'] != 'POST':
                return 405, "".encode('utf-8')
            parameter = request['path'].split('?')[1]
            post_paths = parameter.split('=')[1].split("/")
            post_user = ''
            for parts in post_paths:
                if parts != '':
                    post_user = parts
                    break
            if post_user != http_request.username:
                return 403, ''.encode('utf-8')  # 没body的吧
            root_path = "data"
            for parts in post_paths:
                root_path = os.path.join(root_path, parts)
            # 还要加入 filename, body 还不会解析
            if path == '/upload':
                # upload 的文件夹是否存在
                if not os.path.exists(root_path):
                    return 404, ''.encode('utf-8')
                file_name, file_content = self.get_file(request)
                root_path = os.path.join(root_path, file_name)
                if os.path.exists(root_path):
                    # 新文件名已存在
                    base_name, extension = os.path.splitext(file_name)
                    counter = 1
                    while True:
                        new_filename_with_counter = f"{base_name}({counter}){extension}"
                        root_path = os.path.join(os.path.dirname(root_path), new_filename_with_counter)
                        if not os.path.exists(root_path):
                            # 如果不存在相同的文件名，使用新的文件名
                            break
                        counter += 1
                # print('root_path:', root_path)
                # print('file_content:', file_content)
                open(root_path, 'wb').write(file_content)
                return 200, ''.encode('utf-8')
            if path == '/addDirectory':
                if not os.path.exists(root_path):
                    return 404, ''.encode('utf-8')
                new_directory = request['path'].split('?')[2]
                directory_name = new_directory.split('=')[1]
                root_path = os.path.join(root_path, directory_name)
                if os.path.exists(root_path):
                    # 新文件名已存在
                    base_name, extension = os.path.splitext(directory_name)
                    counter = 1
                    while True:
                        new_filename_with_counter = f"{base_name}({counter}){extension}"
                        root_path = os.path.join(os.path.dirname(root_path), new_filename_with_counter)
                        if not os.path.exists(root_path):
                            # 如果不存在相同的文件名，使用新的文件名
                            break
                        counter += 1
                os.mkdir(root_path)
                return 200, ''.encode('utf-8')
            if path == '/delete':
                file_name = post_paths[-1]
                # root_path = os.path.join(root_path, file_name)
                # delete 的文件是否存在
                print("remove1", root_path)
                if not os.path.isfile(root_path):
                    return 404, ''.encode('utf-8')

                os.remove(root_path)
                return 200, ''.encode('utf-8')
            if path == '/rename':
                # delete 的文件是否存在
                if not os.path.isfile(root_path) and not os.path.isdir(root_path):
                    return 404, ''.encode('utf-8')
                new_filename = request['path'].split('?')[2].split('=')[1]
                new_rootpath = os.path.join(os.path.dirname(root_path), new_filename)
                if os.path.exists(new_rootpath):
                    # 新文件名已存在
                    base_name, extension = os.path.splitext(new_filename)
                    counter = 1
                    while True:
                        new_filename_with_counter = f"{base_name}({counter}){extension}"
                        new_rootpath = os.path.join(os.path.dirname(root_path), new_filename_with_counter)
                        if not os.path.exists(new_rootpath):
                            # 如果不存在相同的文件名，使用新的文件名
                            break
                        counter += 1
                os.rename(root_path, new_rootpath)
                return 200, ''.encode('utf-8')
        else:
            if request['method'] != 'GET':
                return 405, "".encode('utf-8')
            if request['path'] == '/':
                return 200, ''.encode('utf-8')
            root_path = "data"
            for path in paths:
                root_path = os.path.join(root_path, path)
            print("root_path", root_path)
            if os.path.isfile(root_path):
                http_request.file_type, http_request.encoding = self.get_file_type(root_path)
                http_request.file_path = root_path
                http_request.file_size = os.path.getsize(root_path)
                if request['path'].split('?')[-1] == 'chunked=1':
                    # chunk transfer
                    http_request.is_chunked = True
                    return 200, root_path
                else:
                    # simple transfer
                    if 'Range' in request['headers']:
                        code1, body1 = self.breakpoint_transmission(request, root_path, http_request)
                        return code1, body1
                    # print(open(root_path, 'rb').read().decode('utf-8'))
                    if http_request.file_size >= max_file_size:
                        http_request.file_path = root_path
                        http_request.is_large_file = True
                        return 200, root_path
                    return 200, open(root_path, 'rb').read()
            if not os.path.exists(root_path):
                return 404, ''.encode('utf-8')
            html, file_list = self.generate_html(root_path)
            if request['path'].split('?')[-1] == 'SUSTech-HTTP=0':
                http_request.file_type = 'text/html'
                return 200, html.encode('utf-8')
            if request['path'].split('?')[-1] == 'SUSTech-HTTP=1':
                http_request.file_type = 'text/plain'
                return 200, ('[ "' + '", "'.join(file_list) + '"]').encode('utf-8')
            return 400, "".encode('utf-8')

    def breakpoint_transmission(self, request, file_path, http_request):
        body = b''
        ranges = request['headers']['Range'].split(',')
        if len(ranges) == 1:
            # single range

            indexs = ranges[0].replace('bytes=', '').split('-')
            print(indexs)
            start = int(indexs[0])
            end = int(indexs[1]) if indexs[1] != '' else os.path.getsize(file_path) - 1
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

        return 206, body

    def get_authorization(self, request, http_request):
        auth_header = request['headers']['Authorization']
        encoded_credentials = auth_header.split(' ')[1]  # 获取 Basic 后面的编码字符串
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        http_request.username, http_request.password = decoded_credentials.split(':')
        # print(f"Username: {self.username}, Password: {self.password}")
        return http_request.username, http_request.password

    def get_file(self, request):
        boundary = '--' + request['headers']['Content-Type'].split('boundary=')[-1]
        contents = request['body']
        # print(contents)
        start_marker = '\r\n\r\n'.encode('utf-8')
        end_marker = boundary.encode('utf-8')
        start_index = contents.find(start_marker) + len(start_marker)
        end_index = contents.rfind(end_marker)

        file_content = contents[start_index:end_index]
        file_name = request['body'].split('filename="'.encode())[1].split('"\r\n'.encode())[0]
        # print(file_content)
        return file_name.decode('utf-8'), file_content

    def handle_client(self, client_socket):
        while True:
            # try:
            request = self.parse_http_request(client_socket)
            if request['method'] is None:
                break
            http_request = HttpRequest()
            if request['path'].find("%") is not None:
                request['path'] = self.decode_url(request['path'])
                request['path'] = request['path'].encode('iso-8859-1').decode('utf-8')
            print("request method:", request['method'])
            print("request path:", request['path'])
            print("request header:", request['headers'])
            status_code, status_text = self.get_status(request, http_request)
            body = ''
            # if request['method'] == 'GET':
            code, body = self.get_body(status_code, request, http_request)
            if code == 406:
                status_code, status_text = 406, 'Already Exist'
            elif code == 403:
                status_code, status_text = 403, 'Forbidden'
            elif code == 404:
                status_code, status_text = 404, 'Not Found'
            elif code == 405:
                status_code, status_text = 405, 'Method Not Allowed'
            elif code == 400:
                status_code, status_text = 400, 'Bad Request'
            elif code == 206:
                status_code, status_text = 206, 'Partial Content'
            elif code == 200 and status_code == 408:
                status_code, status_text = 200, 'OK'
            elif code == 410 and status_code == 408:
                status_code, status_text = 410, 'Gone'
            headers = self.get_headers(request, status_code, body, http_request)
            print("response status code", status_code)
            print("response status text", status_text)
            print("response headers", headers)
            if http_request.is_chunked:

                # send headers
                client_socket.sendall(
                    self.create_http_response(status_code=status_code, status_text=status_text, headers=headers,
                                              body=""))
                # client_socket.sendall(body)
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
            elif http_request.is_large_file:
                client_socket.sendall(
                    self.create_http_response(status_code=status_code, status_text=status_text, headers=headers,
                                              body=""))
                with open(body, 'rb') as f:
                    while True:
                        data = f.read(chunk_size)
                        if not data:
                            break
                        client_socket.sendall(data)
                        if len(data) < chunk_size:
                            break
                    http_request.is_large_file = False
            else:
                response = self.create_http_response(status_code=status_code, status_text=status_text,
                                                     headers=headers, body=body)
                client_socket.sendall(response)
                client_socket.sendall(body)
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
