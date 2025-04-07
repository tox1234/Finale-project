import socket
import threading
import json
import os


HOST = '127.0.0.1'
PORT = 5000
DB_FILE = "users.json"
USER_DIR = "user_data"


def load_db():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, 'w') as f:
            json.dump({}, f)
    with open(DB_FILE, 'r') as f:
        return json.load(f)


def save_db(db):
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=4)


def handle_client(conn, addr):
    print(f"Connection from {addr}")
    conn.sendall(b'Would you like to [login/register]: ')
    action = conn.recv(1024).decode().strip().lower()

    db = load_db()

    if action == 'register':
        conn.sendall(b'Choose a username: ')
        username = conn.recv(1024).decode().strip()
        if not username:
            conn.sendall(b'Invalid username!\n')
            conn.close()
            return
        if username in db:
            conn.sendall(b'Username already exists!\n')
            conn.close()
            return
        conn.sendall(b'Choose a password: ')
        password = conn.recv(1024).decode().strip()
        if not password:
            conn.sendall(b'Invalid password!\n')
            conn.close()
            return
        db[username] = password
        save_db(db)
        os.makedirs(os.path.join(USER_DIR, username), exist_ok=True)
        conn.sendall(b'Registration successful! Please reconnect to login.\n')
        conn.close()
        return

    elif action == 'login':
        conn.sendall(b'Username: ')
        username = conn.recv(1024).decode().strip()
        conn.sendall(b'Password: ')
        password = conn.recv(1024).decode().strip()

        if username in db and db[username] == password:
            conn.sendall(b'Login successful!\n')
            user_folder = os.path.join(USER_DIR, username)
            os.makedirs(user_folder, exist_ok=True)

            while True:
                conn.sendall(b'Options: [upload/download/exit]: ')
                option = conn.recv(1024).decode().strip()

                if option == 'upload':
                    conn.sendall(b'Enter filename: ')
                    filename = conn.recv(1024).decode().strip()
                    filepath = os.path.join(user_folder, filename)
                    conn.sendall(b'Send file data: ')
                    data = conn.recv(1024)
                    with open(filepath, 'wb') as f:
                        f.write(data)
                    conn.sendall(b'File uploaded successfully!\n')

                elif option == 'download':
                    conn.sendall(b'Enter filename: ')
                    filename = conn.recv(1024).decode().strip()
                    filepath = os.path.join(user_folder, filename)
                    if os.path.exists(filepath):
                        with open(filepath, 'rb') as f:
                            conn.sendall(f.read())
                    else:
                        conn.sendall(b'File not found!\n')

                elif option == 'exit':
                    conn.sendall(b'Goodbye!\n')
                    break
        else:
            conn.sendall(b'Invalid credentials!\n')
    else:
        conn.sendall(b'Invalid option!\n')

    conn.close()


def main():
    os.makedirs(USER_DIR, exist_ok=True)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    main()
