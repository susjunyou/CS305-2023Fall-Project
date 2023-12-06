import argparse
import socket


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
    while not data.endswith("\r\n\r\n"):
        data += sock.recv(1).decode()
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
        while len(body) < length:
            body += sock.recv(1).decode()
    return {"method": method, "path": path, "version": version, "headers": headers, "body": body}


def create_http_response(status_code, status_text, headers, body):
    response = f"HTTP/1.1 {status_code} {status_text}\r\n"
    for key, value in headers.items():
        response += f"{key}: {value}\r\n"
    response += "\r\n"
    response += body
    return response


def listening(server_socket):
    while True:
        # 等待客户端连接
        client_socket, addr = server_socket.accept()
        # 接收客户端发送的数据
        # this request is a dictionary
        request = parse_http_request(client_socket)
        print("request", request)

        # 发送HTTP响应
        response = create_http_response(status_code=200, status_text="OK", headers={"Content-Type": "text/html"},
                                        body="Hello World")
        print("response", response)
        client_socket.send(response.encode('utf-8'))

        # 关闭连接
        client_socket.close()


if __name__ == '__main__':
    host, port = my_parser()
    # 创建一个 socket 对象
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 绑定到指定的端口
    server_socket.bind((host, int(port)))
    # 设置最大连接数
    server_socket.listen(5)
    listening(server_socket)
