import argparse
import base64
import socket
import threading


def my_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--host', type=str)
    parser.add_argument('-p', '--port', type=str)
    args = parser.parse_args()
    host = args.host
    port = args.port
    return host, port


def parse_http_request(sock):
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


def create_http_response(status_code, status_text, headers, body):
    response = f"HTTP/1.1 {status_code} {status_text}\r\n"
    for key, value in headers.items():
        response += f"{key}: {value}\r\n"
    response += "\r\n"
    response += body
    return response


def get_status(request):
    status_code, status_text = 200, 'OK'
    headers = request['headers']
    body = request['body']
    if 'Authorization' in headers:
        username, password = get_Authorization(request)
        if username in user_auth and user_auth[username] == password:
            status_code, status_text = 200, 'OK'
        else:
            status_code, status_text = 401, 'Unauthorized'
    else:
        status_code, status_text = 401, 'Unauthorized'
    return status_code, status_text


def get_headers(request, status_code):
    headers = {"Content-Type": "text/html"}
    if status_code == 401:
        headers['WWW-Authenticate'] = 'Basic realm="Authorization Required"'
    return headers


def get_body(request):
    return "Hello World"


def get_Authorization(request):
    auth_header = request['headers']['Authorization']
    encoded_credentials = auth_header.split(' ')[1]  # 获取 Basic 后面的编码字符串
    decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
    username, password = decoded_credentials.split(':')
    # print(f"Username: {username}, Password: {password}")
    return username, password


def handle_client(client_socket):
    # print("Thread started for client:", threading.current_thread().ident)
    while True:
        try:
            request = parse_http_request(client_socket)
            if request['method'] is None:
                break
            print("request", request)
            status_code, status_text = get_status(request)
            headers = get_headers(request, status_code)
            body = get_body(request) if request['method'] != 'HEAD' else ''
            response = create_http_response(status_code=status_code, status_text=status_text,
                                            headers=headers, body=body)
            print("response", response)
            client_socket.sendall(response.encode())
            if request['headers'].get('Connection') == 'close':
                break
        except Exception as e:
            print(f"Error handling request: {e}")
            break
        # 不知道为什么不关闭连接，test_Demo中的代码中的 Get和 Post都不会停止运行，这不符合持久性连接
        client_socket.close()
        break
    # print("Thread ended for client:", threading.current_thread().ident)


def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, int(port)))
    # 设置最大连接数
    server_socket.listen(7)
    while True:
        client_socket, addr = server_socket.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()


# def listening(server_socket):
#     while True:
#         # 等待客户端连接
#         client_socket, addr = server_socket.accept()
#         # 接收客户端发送的数据
#         # this request is a dictionary
#         request = parse_http_request(client_socket)
#         print("request", request)
#
#         status_code, status_text = get_status(request)
#         # 发送HTTP响应
#         response = create_http_response(status_code=status_code, status_text=status_text,
#                                         headers={"Content-Type": "text/html"}, body="Hello World")
#         print("response", response)
#         client_socket.send(response.encode('utf-8'))
#
#         if request['header']['Connection'] == 'close':
#             # 关闭连接
#             client_socket.close()


if __name__ == '__main__':
    # 用户认证
    user_auth = {'client1': '123'}
    host, port = my_parser()
    start_server(host, port)
