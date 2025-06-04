import socket
import threading
from database_manager import DatabaseManager
from file_manager import FileManager
import ssl
import protocol
import reprlib

HOST = 'localhost'
PORT = 9009
CERT_FILE = 'server_files/certificate.crt'
KEY_FILE = 'server_files/privateKey.key'


def send_msg(conn, *values):
    """
        Sends a message to the client using the defined protocol.
        :param conn: The client socket connection.
        :return: None
    """
    protocol.send_msg(conn, *values)


def recv_msg(conn, num_values):
    """
        Receives a message from the client using the defined protocol.
        :param conn: The client socket connection.
        :param num_values: The number of values expected from the client.
        :return: list: A list of values received from the client.
    """
    return protocol.recv_msg(conn, num_values)


class ServerManager:
    """
    Manages the server-side operations for a secure cloud storage service.

    This class is responsible for initializing the server, handling client
    connections securely using TLS/SSL, processing various client requests
    such as user authentication, file operations (upload, download, view,
    delete, rename), and permission management. It interacts with
    DatabaseManager for user and file metadata operations and FileManager
    for file system interactions. Each client connection is handled in a
    separate thread.
    """

    def __init__(self):
        """
            Initializes the ServerManager.
            Sets up the host, port, database manager, file manager,
            and initializes the server socket and running state.
            :param self: The instance of the ServerManager.
            :return: None
        """
        self.host = HOST
        self.port = PORT
        self.db = DatabaseManager()
        self.file_manager = FileManager()
        self.server_socket = None
        self.running = False

    def handle_register(self, conn, _data=None):
        """
            Handles user registration requests.
            Receives username and password from the client, attempts to register
            the user via DatabaseManager, and sends back a status message.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection.
            :param _data: Optional data (currently unused).
            :return: None
        """
        username, password = recv_msg(conn, 2)
        success, message = self.db.register_user(username, password)
        status_msg = 'ok' if success else 'error'
        send_msg(conn, status_msg, message)

    def handle_login(self, conn, _data=None):
        """
            Handles user login requests.
            Receives username and password, authenticates the user via
            DatabaseManager, and sends back a status message.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection.
            :param _data: Optional data (currently unused).
            :return: dict or None: A user dictionary object if login is
                                   successful, otherwise None.
        """
        username, password = recv_msg(conn, 2)
        user = self.db.authenticate_user(username, password)
        if user:
            send_msg(conn, 'ok', 'Login successful.')
            return user
        send_msg(conn, 'error', 'Invalid credentials.')
        return None

    def handle_list_files(self, conn, user):
        """
            Handles requests to list files owned by or shared with the user.
            Retrieves file lists from DatabaseManager and sends them to the client.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection.
            :param user: The authenticated user object.
            :return: None
        """
        owned, shared = self.db.get_user_files(user['_id'])
        send_msg(conn, 'ok', reprlib.repr(owned), reprlib.repr(shared))

    def handle_upload(self, conn, user, _data=None):
        """
            Handles file upload requests.
            Receives file metadata. If editing, handles potential renames.
            If new, creates a file record. Acquires write lock, receives data,
            releases lock, and writes the file.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection.
            :param user: The authenticated user object.
            :param _data: Optional data (currently unused).
            :return: None
        """
        (old_filename, new_filename,
         filesize_str, is_edit_str, _is_owned_str) = recv_msg(conn, 5)

        try:
            filesize = int(filesize_str)
        except ValueError:
            send_msg(conn, 'error', 'Invalid filesize format.')
            return
        is_edit = is_edit_str == 'True'

        if not old_filename or not new_filename or filesize is None:
            send_msg(conn, 'error', 'Invalid upload parameters.')
            return

        file_doc = self.db.get_file_doc(old_filename, user['_id'])

        if is_edit:
            if not file_doc:
                send_msg(conn, 'error', 'File not found for editing.')
                return
            old_filepath = file_doc['path']
            is_owner = (file_doc['owner_user_id'] == user['_id'])
            has_edit = user['_id'] in file_doc.get('allowed_edit_user_ids', [])

            # Only allow edit if owner or has edit permission
            if not (is_owner or has_edit):
                send_msg(conn, 'error', 'No permission to edit this file.')
                return

            # If this is a rename operation (explicitly requested by owner)
            if old_filename != new_filename and is_owner:
                new_filepath_candidate = self.file_manager.get_file_path(
                    new_filename, file_doc['owner_user_id']
                )
                if self.file_manager.rename_file(old_filepath, new_filepath_candidate):
                    self.db.rename_file(old_filename, new_filename,
                                      user['_id'], new_filepath_candidate)
                    filepath = new_filepath_candidate
                else:
                    send_msg(conn, 'error', 'Failed to rename file during edit.')
                    return
            else:
                # For normal edits, use the original filepath regardless of new_filename
                filepath = old_filepath
        else:
            existing_doc_for_new = self.db.get_file_doc(new_filename, user['_id'])
            if existing_doc_for_new:
                msg = 'File already exists. Use edit or rename to replace.'
                send_msg(conn, 'error', msg)
                return
            filepath = self.file_manager.get_file_path(new_filename, user['_id'])
            self.db.create_file(new_filename, filepath, user['_id'])

        if not filepath:  # Should not happen if logic above is correct
            send_msg(conn, 'error', 'File path could not be determined.')
            return

        try:
            self.file_manager.acquire_write_lock(filepath)
        except RuntimeError as e:
            send_msg(conn, 'error', str(e))
            return

        send_msg(conn, 'ready')
        data_content = b''
        received_bytes = 0
        try:
            while received_bytes < filesize:
                chunk = conn.recv(min(4096, filesize - received_bytes))
                if not chunk:
                    break
                data_content += chunk
                received_bytes += len(chunk)
        finally:
            self.file_manager.release_write_lock(filepath)

        if received_bytes != filesize:
            msg = (f'Only received {received_bytes} of {filesize} bytes. '
                   f'Connection lost.')
            send_msg(conn, 'error', msg)
            return

        if self.file_manager.write_file(filepath, data_content):
            send_msg(conn, 'ok', 'File uploaded.')
        else:
            send_msg(conn, 'error', 'Failed to write file to disk.')

    def handle_download(self, conn, user, _data=None):
        """
            Handles file download requests.
            Receives filename, retrieves file, reads with read lock,
            and sends it to the client.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection.
            :param user: The authenticated user object.
            :param _data: Optional data (currently unused).
            :return: None
        """
        filename, = recv_msg(conn, 1)
        if not filename:
            send_msg(conn, 'error', 'Missing filename.')
            return

        file_doc = self.db.get_file_doc(filename, user['_id'])
        if not file_doc:
            send_msg(conn, 'error', 'File not found or no permission.')
            return

        filepath = file_doc['path']
        success, file_data = self.file_manager.read_file(filepath)

        if not success:
            send_msg(conn, 'error', 'Failed to read file from server.')
            return

        send_msg(conn, 'ready', str(len(file_data)))
        conn.sendall(file_data)
        send_msg(conn, 'ok', 'Download complete.')

    def handle_permission(self, conn, user, _data=None, add=True):
        """
            Handles requests to add or remove file permissions.
            Updates permissions via DatabaseManager.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection.
            :param user: The authenticated user object (owner of the file).
            :param _data: Optional data (currently unused).
            :param add: bool: True to add permission, False to remove.
            :return: None
        """
        filename, target_username, permission_type = recv_msg(conn, 3)

        if not all([filename, target_username, permission_type]):
            send_msg(conn, 'error', 'Missing parameters.')
            return

        target_user = self.db.get_user_by_username(target_username)
        if not target_user:
            send_msg(conn, 'error', 'Target user not found.')
            return
        if target_user['_id'] == user['_id']:
            send_msg(conn, 'error', 'Cannot change permissions for self.')
            return

        success, message = self.db.update_file_permissions(
            filename, user['_id'], target_user['_id'], permission_type, add
        )
        status_msg = 'ok' if success else 'error'
        send_msg(conn, status_msg, message)

    def handle_delete(self, conn, user, _data=None):
        """
            Handles file deletion requests.
            Verifies ownership, deletes file from file system and DB.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection.
            :param user: The authenticated user object.
            :param _data: Optional data (currently unused).
            :return: None
        """
        filename, = recv_msg(conn, 1)
        if not filename:
            send_msg(conn, 'error', 'Missing filename.')
            return

        file_doc = self.db.get_file_doc(filename, user['_id'],
                                        check_permissions=False)
        if not file_doc or file_doc['owner_user_id'] != user['_id']:
            send_msg(conn, 'error', 'File not found or not owner.')
            return

        deleted_from_fs = self.file_manager.delete_file(file_doc['path'])
        deleted_from_db = self.db.delete_file(filename, user['_id'])

        if deleted_from_fs and deleted_from_db:
            send_msg(conn, 'ok', 'File deleted.')
        else:
            msg = ("Failed to fully delete file. FS: "
                   f"{'OK' if deleted_from_fs else 'Fail'}, "
                   f"DB: {'OK' if deleted_from_db else 'Fail'}")
            send_msg(conn, 'error', msg)

    def handle_rename(self, conn, user, _data=None):
        """
            Handles file rename requests.
            Verifies ownership, renames file on disk and updates DB.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection.
            :param user: The authenticated user object.
            :param _data: Optional data (currently unused).
            :return: None
        """
        old_filename, new_filename = recv_msg(conn, 2)

        if not old_filename or not new_filename:
            send_msg(conn, 'error', 'Missing filename(s).')
            return
        if old_filename == new_filename:
            send_msg(conn, 'error', 'New name must be different from old name.')
            return

        file_doc = self.db.get_file_doc(old_filename, user['_id'],
                                        check_permissions=False)
        if not file_doc or file_doc['owner_user_id'] != user['_id']:
            send_msg(conn, 'error', 'File not found or not owner.')
            return

        new_filepath = self.file_manager.get_file_path(new_filename,
                                                       str(user['_id']))

        renamed_fs = self.file_manager.rename_file(file_doc['path'],
                                                   new_filepath)
        renamed_db = self.db.rename_file(old_filename, new_filename,
                                         user['_id'], new_filepath)

        if renamed_fs and renamed_db:
            send_msg(conn, 'ok', 'File renamed.')
        else:
            msg = ("Failed to fully rename file. FS: "
                   f"{'OK' if renamed_fs else 'Fail'}, "
                   f"DB: {'OK' if renamed_db else 'Fail'}")
            send_msg(conn, 'error', msg)

    def handle_view(self, conn, user, _data=None):
        """
            Handles requests to view file content.
            Verifies permission, acquires read lock, reads data,
            sends it, and releases lock.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection.
            :param user: The authenticated user object.
            :param _data: Optional data (currently unused).
            :return: None
        """
        filename, = recv_msg(conn, 1)
        if not filename:
            send_msg(conn, 'error', 'Missing filename.')
            return

        file_doc = self.db.get_file_doc(filename, user['_id'])
        if not file_doc:
            send_msg(conn, 'error', 'File not found or no permission.')
            return

        filepath = file_doc['path']
        lock_acquired = False
        try:
            self.file_manager.acquire_read_lock(filepath)
            lock_acquired = True
            success, file_data = self.file_manager.read_file(filepath)
            if not success:
                send_msg(conn, 'error', 'Failed to read file from disk.')
                return

            send_msg(conn, 'ready', str(len(file_data)))
            conn.sendall(file_data)
            send_msg(conn, 'ok', 'View complete.')
        except RuntimeError as e_lock:
            send_msg(conn, 'error', str(e_lock))
        finally:
            if lock_acquired:
                self.file_manager.release_read_lock(filepath)

    def handle_check_file_exists(self, conn, user):
        """
            Handles requests to check if a file exists for the user.
            Checks if user owns or has shared access to the file.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection.
            :param user: The authenticated user object.
            :return: None
        """
        filename, = recv_msg(conn, 1)
        file_doc = self.db.get_file_doc(filename, user['_id'])
        if file_doc:
            send_msg(conn, 'yes')
        else:
            send_msg(conn, 'no')

    def handle_client(self, conn, addr):
        """
            Main loop for handling an individual client's requests.
            Continuously receives actions and dispatches to handlers.
            Requires login for most actions.
            :param self: The instance of the ServerManager.
            :param conn: The client socket connection (SSL wrapped).
            :param addr: The client address.
            :return: None
        """
        print(f"New connection from {addr}")
        user = None

        action_handlers = {
            'register': self.handle_register,
            'login': lambda c, u: self.handle_login(c),
        }
        authenticated_action_handlers = {
            'check_file_exists': self.handle_check_file_exists,
            'list_files': self.handle_list_files,
            'upload': self.handle_upload,
            'download': self.handle_download,
            'view': self.handle_view,
            'add_permission': lambda c, u: self.handle_permission(c, u, add=True),
            'remove_permission': lambda c, u: self.handle_permission(c, u, add=False),
            'delete': self.handle_delete,
            'rename': self.handle_rename,
        }

        try:
            while True:
                try:
                    action_tuple = recv_msg(conn, 1)
                    if not action_tuple:  # Connection closed gracefully by client
                        break
                    action = action_tuple[0]
                except ConnectionError:
                    print(f"Connection error with {addr}. Closing connection.")
                    break
                except TypeError:  # If recv_msg returns None due to closed socket
                    print(f"Connection with {addr} appears closed. Terminating handler.")
                    break

                if user:  # User is logged in
                    handler = authenticated_action_handlers.get(action)
                    if handler:
                        handler(conn, user)
                    elif action in action_handlers:  # e.g. trying to login/register again
                        if action == 'login':  # Special case if already logged in
                            user = action_handlers[action](conn, user)
                        else:
                            action_handlers[action](conn, user)  # Or pass user if needed
                    else:
                        send_msg(conn, 'error', f'Unknown action: {action}')
                else:  # User is not logged in
                    handler = action_handlers.get(action)
                    if handler:
                        if action == 'login':
                            user = handler(conn, None)  # Login returns user
                        else:
                            handler(conn, None)  # Other non-auth actions
                    else:
                        send_msg(conn, 'error', 'Not logged in and action requires authentication.')

        except Exception as e:
            print(f"Unexpected error handling client {addr}: {e}. Traceback follows.")
            import traceback
            traceback.print_exc()
        finally:
            if user:
                print(f"Closing connection for user {user.get('username', 'Unknown')} from {addr}")
            else:
                print(f"Closing connection for unauthenticated client from {addr}")
            conn.close()

    def start(self) -> None:
        """
            Starts the server with TLS/SSL.
            Binds to host/port, sets up SSL context, and listens.
            New connections are SSL-wrapped and handled in new daemon threads.
            :param self: The instance of the ServerManager.
            :return: None
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET,
                                      socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
        except OSError as e:
            print(f"Error binding to {self.host}:{self.port} - {e}")
            return

        self.server_socket.listen(5)
        self.running = True

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        except FileNotFoundError:
            print(f"Error: SSL certificate or key file not found. "
                  f"Expected cert: {CERT_FILE}, key: {KEY_FILE}")
            self.stop()
            return
        except ssl.SSLError as e:
            print(f"Error loading SSL certificate/key: {e}")
            self.stop()
            return

        print(f"Server started on {self.host}:{self.port} (TLS enabled)")

        try:
            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                    ssl_conn = context.wrap_socket(conn, server_side=True)
                    client_thread = threading.Thread(
                        target=self.handle_client, args=(ssl_conn, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:  # Socket closed during accept
                    if not self.running:
                        print("Server socket closed, shutting down listener.")
                        break
                    else:
                        print("Error accepting connection, server still running.")
                        # Potentially add a small delay or error counter
        except KeyboardInterrupt:
            print("\nShutting down server via KeyboardInterrupt...")
        finally:
            self.stop()

    def stop(self) -> None:
        """
            Stops the server.
            Sets the running flag to False and closes the server socket.
            :param self: The instance of the ServerManager.
            :return: None
        """
        print("Stopping server...")
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError as e:
                print(f"Error closing server socket: {e}")
            self.server_socket = None
        print("Server stopped.")


if __name__ == '__main__':
    server = ServerManager()
    server.start()
