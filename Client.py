import socket

HOST = '127.0.0.1'
PORT = 5000


def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    print(client.recv(1024).decode(), end='')
    action = input()
    client.sendall(action.encode())

    if action.lower().strip() == 'register':
        print(client.recv(1024).decode(), end='')
        username = input()
        client.sendall(username.encode())

        print(client.recv(1024).decode(), end='')
        password = input()
        client.sendall(password.encode())

        print(client.recv(1024).decode())
        client.close()
        return

    print(client.recv(1024).decode(), end='')
    username = input()
    client.sendall(username.encode())

    print(client.recv(1024).decode(), end='')
    password = input()
    client.sendall(password.encode())

    response = client.recv(1024).decode()
    print(response)

    if "Login successful" in response:
        while True:
            print(client.recv(1024).decode(), end='')
            option = input()
            client.sendall(option.encode())

            if option == 'upload':
                print(client.recv(1024).decode(), end='')
                filename = input()
                client.sendall(filename.encode())

                try:
                    with open(filename, 'rb') as f:
                        data = f.read()
                    client.sendall(data)
                    print(client.recv(1024).decode())
                except FileNotFoundError:
                    print("File not found!")

            elif option == 'download':
                print(client.recv(1024).decode(), end='')
                filename = input()
                client.sendall(filename.encode())

                data = client.recv(1024)
                if b'File not found' in data:
                    print(data.decode())
                else:
                    with open(filename, 'wb') as f:
                        f.write(data)
                    print("File downloaded successfully!")

            elif option == 'exit':
                print(client.recv(1024).decode())
                break

    client.close()


if __name__ == "__main__":
    main()
