# server.py
import os
import socket
import threading
import json
import hashlib

from pymongo import MongoClient

# --- Configuration ---
HOST = 'localhost'
PORT = 9009
BASE_DIR = 'server_files'

os.makedirs(BASE_DIR, exist_ok=True)

client = MongoClient('mongodb://localhost:27017/')
db = client['cloud_storage']
users_col = db['users']
files_col = db['files']

users_col.create_index('username', unique=True)
files_col.create_index('filename', unique=True)

file_locks = {}


def get_file_locks(filepath):
    """Initialize lock structure for a file path if not present."""
    if filepath not in file_locks:
        file_locks[filepath] = {
            'readers': 0,
            'read_lock': threading.Lock(),
            'write_lock': threading.Lock()
        }
    return file_locks[filepath]


def hash_password(password):
    """Return a hex SHA-256 hash of the password."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def send_json(conn, data):
    """Send a JSON-serializable object over the socket (with newline)."""
    msg = json.dumps(data) + '\n'
    conn.sendall(msg.encode('utf-8'))


def recv_json(conn):
    """Receive a JSON object terminated by newline."""
    buffer = b''
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buffer += chunk
        if b'\n' in buffer:
            line, rest = buffer.split(b'\n', 1)
            try:
                return json.loads(line.decode('utf-8'))
            except json.JSONDecodeError:
                return None


def handle_register(conn, data):
    """Handle user registration."""
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        send_json(conn, {"status": "error", "message": "Missing username or password."})
        return
    if users_col.find_one({"username": username}):
        send_json(conn, {"status": "error", "message": "Username already exists."})
    else:
        pwd_hash = hash_password(password)
        users_col.insert_one({"username": username, "password_hash": pwd_hash})
        send_json(conn, {"status": "ok", "message": "Registered successfully."})


def handle_login(conn, data):
    """Handle user login. Returns the user document on success."""
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        send_json(conn, {"status": "error", "message": "Missing username or password."})
        return None
    user = users_col.find_one({"username": username})
    if not user or user['password_hash'] != hash_password(password):
        send_json(conn, {"status": "error", "message": "Invalid credentials."})
        return None
    send_json(conn, {"status": "ok", "message": "Login successful."})
    return user


def handle_list_files(conn, user):
    """Send the list of owned and shared files for this user."""
    uid = user['_id']
    owned_cursor = files_col.find({"owner_user_id": uid})
    owned = [doc['filename'] for doc in owned_cursor]

    # Files shared where user has read or edit access (but skip those they own)
    shared_docs = files_col.find({
        "owner_user_id": {"$ne": uid},
        "$or": [
            {"allowed_read_user_ids": uid},
            {"allowed_edit_user_ids": uid}
        ]
    })
    shared = []
    for doc in shared_docs:
        perm = "edit" if uid in doc.get('allowed_edit_user_ids', []) else "read"
        shared.append({"filename": doc['filename'], "perm": perm})

    send_json(conn, {"status": "ok", "owned": owned, "shared": shared})


def handle_upload(conn, user, data):
    """Handle uploading (new file or edit)."""
    # FIX 1: Sanitize filename to prevent path traversal
    filename = os.path.basename(data.get('filename'))  # Critical fix here
    filesize = data.get('filesize')
    if not filename or filesize is None:
        send_json(conn, {"status": "error", "message": "Invalid upload parameters."})
        return
    uid = user['_id']
    file_doc = files_col.find_one({"filename": filename})
    is_new = (file_doc is None)
    # Determine if user is allowed to upload
    if is_new:
        # New file: make this user the owner
        owner_id = uid
        file_subdir = os.path.join(BASE_DIR, str(uid))
        os.makedirs(file_subdir, exist_ok=True)
        filepath = os.path.join(file_subdir, filename)
        # Insert DB document
        files_col.insert_one({
            "filename": filename,
            "path": filepath,
            "owner_user_id": owner_id,
            "allowed_read_user_ids": [],
            "allowed_edit_user_ids": []
        })
    else:
        owner_id = file_doc['owner_user_id']
        filepath = file_doc['path']
        if uid != owner_id and uid not in file_doc.get('allowed_edit_user_ids', []):
            send_json(conn, {"status": "error", "message": "No edit permission."})
            return
    # Ready to receive file data
    send_json(conn, {"status": "ready"})
    # Acquire write lock for this file
    locks = get_file_locks(filepath)
    locks['write_lock'].acquire()
    try:
        # Write file content
        with open(filepath, 'wb') as f:
            remaining = filesize
            while remaining > 0:
                chunk = conn.recv(min(4096, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)
    finally:
        locks['write_lock'].release()
    send_json(conn, {"status": "ok", "message": "File uploaded."})


def handle_download(conn, user, data):
    """Handle file download (sending file to client)."""
    filename = data.get('filename')
    if not filename:
        send_json(conn, {"status": "error", "message": "Missing filename."})
        return
    uid = user['_id']
    print(filename)
    file_doc = files_col.find_one({"filename": filename})
    if not file_doc:
        send_json(conn, {"status": "error", "message": "File not found."})
        return
    owner_id = file_doc['owner_user_id']
    if uid != owner_id and uid not in file_doc.get('allowed_read_user_ids', []) \
            and uid not in file_doc.get('allowed_edit_user_ids', []):
        send_json(conn, {"status": "error", "message": "No read permission."})
        return
    filepath = file_doc['path']
    if not os.path.exists(filepath):
        send_json(conn, {"status": "error", "message": "File missing on server."})
        return
    filesize = os.path.getsize(filepath)
    # Ready to send
    send_json(conn, {"status": "ready", "filesize": filesize})
    # Acquire read lock
    locks = get_file_locks(filepath)
    locks['read_lock'].acquire()
    locks['readers'] += 1
    if locks['readers'] == 1:
        locks['write_lock'].acquire()
    locks['read_lock'].release()

    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                conn.sendall(chunk)
    finally:
        locks['read_lock'].acquire()
        locks['readers'] -= 1
        if locks['readers'] == 0:
            locks['write_lock'].release()
        locks['read_lock'].release()
    send_json(conn, {"status": "ok", "message": "Download complete."})


def handle_add_permission(conn, user, data, add=True):
    """Handle adding or removing permission (read/edit) for a file."""
    filename = data.get('file')
    target_username = data.get('target_user')
    perm = data.get('permission')  # "read" or "edit"
    if not (filename and target_username and perm):
        send_json(conn, {"status": "error", "message": "Invalid parameters."})
        return
    uid = user['_id']
    file_doc = files_col.find_one({"filename": filename})
    if not file_doc:
        send_json(conn, {"status": "error", "message": "File not found."})
        return
    if file_doc['owner_user_id'] != uid:
        send_json(conn, {"status": "error", "message": "Only owner can change permissions."})
        return
    target_user = users_col.find_one({"username": target_username})
    if not target_user:
        send_json(conn, {"status": "error", "message": "Target user not found."})
        return
    tid = target_user['_id']
    field = 'allowed_read_user_ids' if perm == 'read' else 'allowed_edit_user_ids'
    if add:
        # Add target to list if not already present
        if tid in file_doc.get(field, []):
            send_json(conn, {"status": "error", "message": "User already has that permission."})
            return
        files_col.update_one({"filename": filename}, {"$push": {field: tid}})
        send_json(conn, {"status": "ok", "message": f"Added {perm} permission."})
    else:
        # Remove target from list
        if tid not in file_doc.get(field, []):
            send_json(conn, {"status": "error", "message": "User does not have that permission."})
            return
        files_col.update_one({"filename": filename}, {"$pull": {field: tid}})
        send_json(conn, {"status": "ok", "message": f"Removed {perm} permission."})


def handle_delete(conn, user, data):
    """Delete a file (owner only)."""
    filename = data.get('filename')
    if not filename:
        send_json(conn, {"status": "error", "message": "Missing filename."})
        return
    file_doc = files_col.find_one({"filename": filename})
    if not file_doc:
        send_json(conn, {"status": "error", "message": "File not found."})
        return
    uid = user['_id']
    if file_doc['owner_user_id'] != uid:
        send_json(conn, {"status": "error", "message": "Only owner may delete."})
        return
    # Remove from disk
    try:
        os.remove(file_doc['path'])
    except OSError:
        pass
    files_col.delete_one({"_id": file_doc['_id']})
    send_json(conn, {"status": "ok", "message": f"Deleted '{filename}'."})


def handle_rename(conn, user, data):
    """Rename a file (owner or edit-permitted), preserving its original extension."""
    old_name = data.get('old_filename')
    raw_new = data.get('new_filename') or ""
    if not old_name or not raw_new:
        send_json(conn, {"status":"error","message":"Missing filenames."})
        return

    # Lookup
    file_doc = files_col.find_one({"filename": old_name})
    if not file_doc:
        send_json(conn, {"status":"error","message":"File not found."})
        return

    uid = user['_id']
    allowed_edit = file_doc.get('allowed_edit_user_ids', [])
    if uid != file_doc['owner_user_id'] and uid not in allowed_edit:
        send_json(conn, {"status":"error","message":"No permission to rename."})
        return

    # Preserve extension
    base_old, ext_old = os.path.splitext(old_name)
    base_new, _ = os.path.splitext(os.path.basename(raw_new))
    new_name = base_new + ext_old

    # Paths
    dirpath  = os.path.dirname(file_doc['path'])
    old_path = file_doc['path']
    new_path = os.path.join(dirpath, new_name)

    # Rename on disk
    try:
        os.rename(old_path, new_path)
    except OSError as e:
        send_json(conn, {"status":"error","message":f"OS error: {e}"})
        return

    # Update DB
    files_col.update_one(
        {"_id": file_doc['_id']},
        {"$set": {"filename": new_name, "path": new_path}}
    )
    send_json(conn, {"status":"ok","message":f"Renamed to '{new_name}'."})


def handle_client(conn, addr):
    """Main loop for client thread."""
    print(f"Connected by {addr}")
    current_user = None
    try:
        while True:
            data = recv_json(conn)
            if data is None:
                break  # connection closed
            action = data.get('action')
            if action == 'register':
                handle_register(conn, data)
            elif action == 'login':
                if current_user:
                    send_json(conn, {"status": "error", "message": "Already logged in."})
                else:
                    user = handle_login(conn, data)
                    if user:
                        current_user = user
            elif action == 'logout':
                send_json(conn, {"status": "ok", "message": "Logged out."})
                break
            else:
                # The rest require login
                if not current_user:
                    send_json(conn, {"status": "error", "message": "Please login first."})
                    continue
                if action == 'list_files':
                    handle_list_files(conn, current_user)
                elif action == 'upload':
                    handle_upload(conn, current_user, data)
                elif action == 'download':
                    handle_download(conn, current_user, data)
                elif action == 'add_permission':
                    handle_add_permission(conn, current_user, data, add=True)
                elif action == 'remove_permission':
                    handle_add_permission(conn, current_user, data, add=False)
                elif action == 'delete':
                    handle_delete(conn, current_user, data)
                elif action == 'rename':
                    handle_rename(conn, current_user, data)
                else:
                    send_json(conn, {"status": "error", "message": "Unknown action."})
    except Exception as e:
        print(f"Error with client {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection closed {addr}")


def start_server():
    """Set up the listening socket and accept clients."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()


if __name__ == '__main__':
    start_server()
