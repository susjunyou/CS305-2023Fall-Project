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
    while True:

        # 等待客户端连接
        client_socket, addr = server_socket.accept()
        # 接收客户端发送的数据
        data = client_socket.recv(1024).decode('utf-8')
        print(data)
        # 解封装
        lines = data.strip().split('\r\n')
        headers = {}
        method, path, protocol = lines[0].split(' ')
        for line in lines[1:]:
            key, value = line.split(': ')
            headers[key] = value
        headers['method'] = method
        headers['path'] = path
        headers['protocol'] = protocol

        print(headers)  # 打印字典

        # 发送HTTP响应
        response = 'HTTP/1.0 200 OK\n\nThank you for connecting'
        client_socket.send(response.encode('utf-8'))

        # 关闭连接
        client_socket.close()