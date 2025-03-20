import socket
import os


HOST = '0.0.0.0'  
PORT = 5001
FILES_DIR = "server_files"  


def fix_end(chunk_):
    temp = chunk_.decode()
    print(temp)
    temp = temp[:-3]
    return temp.encode()


if not os.path.exists(FILES_DIR):
    os.makedirs(FILES_DIR)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

print(f"Server is listening on {HOST}:{PORT}")

while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    request_type = client_socket.recv(1024).decode()

    if request_type == "DOWNLOAD":

        requested_file = client_socket.recv(1024).decode()
        file_path = os.path.join(FILES_DIR, requested_file)

        if os.path.exists(file_path):
            client_socket.send(b"FOUND")
            with open(file_path, "rb") as file:
                while chunk := file.read(1024):
                    client_socket.send(chunk) 
            print(f"File '{requested_file}' sent successfully.")
        else:
            client_socket.send(b"NOT FOUND")
            print(f"File '{requested_file}' not found.")

    elif request_type == "UPLOAD":
        file_name = client_socket.recv(1024).decode()
        file_path = os.path.join(FILES_DIR, file_name)

        with open(file_path, "wb") as file:
            while chunk := client_socket.recv(1024):
                if chunk == b"END":
                    break
                file.write(fix_end(chunk))
        print(f"File '{file_name}' uploaded successfully.")

    client_socket.close()
