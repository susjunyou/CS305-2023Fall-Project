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


if __name__ == '__main__':
    host, port = my_parser()
    # print(host, port)

    # 创建一个 socket 对象
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 绑定到指定的端口
    server_socket.bind((host, int(port)))

    # 设置最大连接数
    server_socket.listen(5)

    print(f"Server is listening on port {port}")

    while True:
        # 等待客户端连接
        client_socket, addr = server_socket.accept()

        print(f"Got a connection from {addr}")

        # 接收客户端发送的数据
        data = client_socket.recv(1024)
        print(f"Received data: {data.decode('utf-8')}")

        # 发送HTTP响应
        response = 'HTTP/1.0 200 OK\n\nThank you for connecting'
        client_socket.send(response.encode('utf-8'))

        # 关闭连接
        client_socket.close()