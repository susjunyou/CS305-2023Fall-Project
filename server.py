import argparse
import base64
import socket
import threading


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

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        # 设置最大连接数
        server_socket.listen(7)
        while True:
            client_socket, addr = server_socket.accept()
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
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

    def get_headers(self, request, status_code):
        headers = {"Content-Type": "text/html", "Content-Length": "0", "Connection":"keep-alive"}

        if status_code == 401:
            headers['WWW-Authenticate'] = 'Basic realm="Authorization Required"'
        return headers

    def get_body(self, request):
        return "Hello World"

    def get_authorization(self, request):
        auth_header = request['headers']['Authorization']
        encoded_credentials = auth_header.split(' ')[1]  # 获取 Basic 后面的编码字符串
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':')
        # print(f"Username: {username}, Password: {password}")
        return username, password

    def handle_client(self, client_socket):
        print("Thread started for client:", threading.current_thread().ident)
        while True:
            try:
                request = self.parse_http_request(client_socket)
                if request['method'] is None:
                    break
                print("request", request)
                status_code, status_text = self.get_status(request)
                headers = self.get_headers(request, status_code)
                body = self.get_body(request) if request['method'] != 'HEAD' else ''
                response = self.create_http_response(status_code=status_code, status_text=status_text,
                                                     headers=headers, body="")
                print("response", response)
                client_socket.sendall(response.encode())
                if request['headers'].get('Connection').lower() == 'close':
                    break
            except Exception as e:
                print(f"Error handling request: {e}")
                break
            # 不知道为什么不关闭连接，test_Demo中的代码中的 Get和 Post都不会停止运行，这不符合持久性连接
        client_socket.close()
        # break
        print("Thread ended for client:", threading.current_thread().ident)


if __name__ == '__main__':
    # 用户认证
    user_auth = {'client1': '123'}
    host, port = my_parser()
    http_server = HttpServer(host, port)
    http_server.start_server()
