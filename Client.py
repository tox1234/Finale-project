import socket


SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5001


action = input("Choose action - UPLOAD or DOWNLOAD: ").strip().upper()

if action not in ["UPLOAD", "DOWNLOAD"]:
    print("Invalid action. Please choose UPLOAD or DOWNLOAD.")
    exit()


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))


client_socket.send(action.encode())

if action == "DOWNLOAD":
    file_name = input("Enter the name of the file to download: ")
    client_socket.send(file_name.encode())

    response = client_socket.recv(1024).decode()

    if response == "FOUND":
        with open(file_name, "wb") as file:
            while chunk := client_socket.recv(1024):
                file.write(chunk)
        print(f"File '{file_name}' downloaded successfully.")
    else:
        print(f"File '{file_name}' not found on server.")

elif action == "UPLOAD":
    file_name = input("Enter the name of the file to upload: ")
    try:
        with open(file_name, "rb") as file:
            client_socket.send(file_name.encode())
            while chunk := file.read(1024):
                client_socket.send(chunk)
            client_socket.send(b"END")
        print(f"File '{file_name}' uploaded successfully.")
    except FileNotFoundError:
        print(f"File '{file_name}' not found on client.")

client_socket.close()
