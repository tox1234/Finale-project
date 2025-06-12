"""
Author: Ido Shema
Last_updated: 12/06/2025
Description: client manager
"""

import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import os
import ast
from typing import Dict, List, Tuple
from PIL import Image, ImageTk
import io
import tempfile
import fitz
import ssl
import protocol

HOST = 'localhost'
PORT = 9009


class CloudClient:
    def __init__(self):
        """
            Initializes the CloudClient instance.
            Sets the host and port for the server and attempts to establish a connection.
            :param : self: The instance of the CloudClient.
            :return: None
        """
        self.host = HOST
        self.port = PORT
        self.sock = None
        self.user = None
        self.connect()

    def connect(self) -> bool:
        """
            Establishes a secure (TLS/SSL) connection to the server.
            Uses default SSL context with no hostname check and no certificate verification (for development/testing).
            :param : self: The instance of the CloudClient.
            :return: bool: True if the connection was successful, False otherwise.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock = context.wrap_socket(raw_sock, server_hostname=self.host)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            messagebox.showerror("Connection Error", f"Cannot connect to server: {e}")
            return False

    def send_msg(self, *values):
        """
            Sends a message with the given values to the server using the protocol.
            :param : self: The instance of the CloudClient.
            :param : *values: The values to be packed and sent as a message.
            :return: None
        """
        protocol.send_msg(self.sock, *values)

    def recv_msg(self, num_values):
        """
            Receives a message with a specified number of values from the server using the protocol.
            :param : self: The instance of the CloudClient.
            :param : num_values: The expected number of values in the received message.
            :return: tuple: The unpacked values from the message.
        """
        return protocol.recv_msg(self.sock, num_values)

    def register(self, username: str, password: str) -> Tuple[bool, str]:
        """
            Registers a new user on the server.
            Sends a 'register' command along with the username and password.
            :param : self: The instance of the CloudClient.
            :param : username: The username for the new user.
            :param : password: The password for the new user.
            :return: Tuple[bool, str]: A tuple containing a boolean indicating success (True) or failure (False),
                                     and a message from the server.
        """
        self.send_msg('register', username, password)
        status, message = self.recv_msg(2)
        return status == 'ok', message

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
            Logs in an existing user to the server.
            Sends a 'login' command with the username and password. Sets self.user if successful.
            :param : self: The instance of the CloudClient.
            :param : username: The username of the user.
            :param : password: The password of the user.
            :return: Tuple[bool, str]: A tuple containing a boolean indicating success (True) or failure (False),
                                     and a message from the server. If successful, self.user is updated.
        """
        self.send_msg('login', username, password)
        status, message = self.recv_msg(2)
        if status == 'ok':
            self.user = {"username": username}
        return status == 'ok', message

    def list_files(self) -> Tuple[bool, List[str], List[Dict[str, str]]]:
        """
            Retrieves lists of files owned by the user and files shared with the user from the server.
            Sends a 'list_files' command.
            :param : self: The instance of the CloudClient.
            :return: Tuple[bool, List[str], List[Dict[str, str]]]:
                     A tuple containing:
                     - bool: True if the request was successful, False otherwise.
                     - List[str]: A list of filenames owned by the user.
                     - List[Dict[str, str]]: A list of dictionaries, where each dictionary represents a shared file
                                             (e.g., {'filename': 'name', 'perm': 'permission'}).
                     Returns (False, [], []) on failure.
        """
        self.send_msg('list_files')
        status, owned, shared = self.recv_msg(3)
        if status != 'ok':
            return False, [], []
        return True, ast.literal_eval(owned), ast.literal_eval(shared)

    def upload_file(self, filepath: str, is_edit: bool = False, is_owned: bool = False, old_filename: str = None,
                    new_filename: str = None) -> tuple:
        """
            Uploads a file to the server. Can handle new uploads or editing (replacing) existing files.
            Checks for file existence on the server for new uploads and prompts for replacement.
            :param : self: The instance of the CloudClient.
            :param : filepath: The local path to the file to be uploaded.
            :param : is_edit: Boolean, True if this is an edit of an existing file (default False).
            :param : is_owned: Boolean, True if the file being edited is owned by the user (default False).
            :param : old_filename: The name of the file on the server if is_edit is True.
            :param : new_filename: The desired name for the file on the server. Defaults to os.path.basename(filepath).
            :return: tuple: A tuple (bool, str) indicating success (True, message) or failure (False, error_message).
        """
        if not new_filename:
            new_filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        if not is_edit:
            self.send_msg('check_file_exists', new_filename)
            exists, = self.recv_msg(1)
            if exists == 'yes':
                if not messagebox.askyesno("Replace File?",
                                           f"A file named '{new_filename}' already exists. Do you want to replace it?"):
                    return False, "Upload cancelled by user."
                is_edit = True
                old_filename = new_filename
        if is_edit:
            self.send_msg('upload', old_filename, new_filename, str(filesize), str(is_edit), str(is_owned))
        else:
            self.send_msg('upload', new_filename, new_filename, str(filesize), str(is_edit), str(is_owned))
        status, = self.recv_msg(1)
        if status != 'ready':
            return False, status
        try:
            with open(filepath, 'rb') as f:
                sent = 0
                while sent < filesize:
                    chunk = f.read(min(4096, filesize - sent))
                    if not chunk:
                        break
                    self.sock.sendall(chunk)
                    sent += len(chunk)
            if sent != filesize:
                return False, f"Only sent {sent} of {filesize} bytes. Connection lost."
        except Exception as e:
            return False, f"Error reading file: {e}"
        status, message = self.recv_msg(2)
        if status == 'ok':
            messagebox.showinfo("Success", "Successfully updated the file.")
        return status == 'ok', message

    def download_file(self, filename: str, save_path: str) -> Tuple[bool, str]:
        """
            Downloads a file from the server and saves it to the specified local path.
            Sends a 'download' command.
            :param : self: The instance of the CloudClient.
            :param : filename: The name of the file to download from the server.
            :param : save_path: The local path where the downloaded file should be saved.
            :return: Tuple[bool, str]: A tuple indicating success (True, message) or failure (False, error_message).
        """
        self.send_msg('download', filename)
        status, filesize_str = self.recv_msg(2)
        if status != 'ready':
            return False, filesize_str

        try:
            filesize = int(filesize_str)
        except ValueError:
            return False, "Invalid filesize from server."

        try:
            with open(save_path, 'wb') as f:
                remaining = filesize
                while remaining > 0:
                    chunk = self.sock.recv(min(4096, remaining))
                    if not chunk:
                        raise ConnectionError("Connection lost during download.")
                    f.write(chunk)
                    remaining -= len(chunk)
        except Exception as e:
            return False, f"Error writing file: {e}"

        status, message = self.recv_msg(2)
        return status == 'ok', message

    def change_permission(self, filename: str, target_user: str, permission: str, add: bool) -> Tuple[bool, str]:
        """
            Changes file permissions for a target user on a specific file.
            Sends 'add_permission' or 'remove_permission' command.
            :param : self: The instance of the CloudClient.
            :param : filename: The name of the file whose permissions are to be changed.
            :param : target_user: The username of the user for whom permissions are being set/revoked.
            :param : permission: The permission type (e.g., 'read', 'edit').
            :param : add: Boolean, True to add the permission, False to remove it.
            :return: Tuple[bool, str]: A tuple indicating success (True, message) or failure (False, error_message).
        """
        action = 'add_permission' if add else 'remove_permission'
        self.send_msg(action, filename, target_user, permission)
        status, message = self.recv_msg(2)
        return status == 'ok', message

    def delete_file(self, filename: str) -> Tuple[bool, str]:
        """
            Deletes a file from the server.
            Sends a 'delete' command.
            :param : self: The instance of the CloudClient.
            :param : filename: The name of the file to be deleted.
            :return: Tuple[bool, str]: A tuple indicating success (True, message) or failure (False, error_message).
        """
        self.send_msg('delete', filename)
        status, message = self.recv_msg(2)
        return status == 'ok', message

    def rename_file(self, old_filename: str, new_filename: str) -> Tuple[bool, str]:
        """
            Renames a file on the server.
            Sends a 'rename' command.
            :param : self: The instance of the CloudClient.
            :param : old_filename: The current name of the file on the server.
            :param : new_filename: The new desired name for the file.
            :return: Tuple[bool, str]: A tuple indicating success (True, message) or failure (False, error_message).
        """
        self.send_msg('rename', old_filename, new_filename)
        status, message = self.recv_msg(2)
        return status == 'ok', message


class CloudClientGUI:
    def __init__(self, master: tk.Tk):
        """
            Initializes the CloudClientGUI application.
            Sets up the main window, initializes the CloudClient, and creates the splash/login UI.
            :param self: The instance of CloudClientGUI.
            :param master: The root tk.Tk window for the application.
            :return: None. The application window will be destroyed if client connection fails.
        """
        self.master = master
        master.title("Cloud Client")
        master.geometry("1024x768")
        master.configure(bg='#0a0a0a')

        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)

        self.client = CloudClient()
        if not self.client.sock:
            master.destroy()
            return

        self.setup_styles()
        self.create_splash_screen()
        self.create_login_frame()

    def setup_styles(self):
        """
            Configures the visual styles for Tkinter widgets using a modern dark theme.
            Sets up colors and fonts for labels, buttons, entries, etc.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        self.style = ttk.Style()
        self.style.theme_use('clam')

        bg_color = '#0a0a0a'
        entry_bg = '#1f1f1f'
        button_bg = '#2a2a2a'
        text_color = '#ffffff'
        accent_color = '#404040'

        self.style.configure('TFrame', background=bg_color)
        self.style.configure('TLabel', background=bg_color, foreground=text_color, font=('Segoe UI', 12))
        self.style.configure('TButton',
                             background=button_bg,
                             foreground=text_color,
                             font=('Segoe UI', 11, 'bold'),
                             borderwidth=0,
                             padding=8)
        self.style.map('TButton',
                       background=[('active', accent_color), ('!active', button_bg)],
                       relief=[('pressed', 'sunken'), ('!pressed', 'flat')])
        self.style.configure('TEntry',
                             fieldbackground=entry_bg,
                             foreground=text_color,
                             insertcolor=text_color,
                             borderwidth=0,
                             padding=8,
                             font=('Segoe UI', 12))

    def create_splash_screen(self):
        """
            Creates and displays an animated splash screen upon application startup.
            The splash screen shows loading text and an indeterminate progress bar.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        self.splash_frame = ttk.Frame(self.master)
        self.splash_frame.grid(row=0, column=0, sticky='nsew')

        self.splash_frame.grid_rowconfigure(0, weight=1)
        self.splash_frame.grid_columnconfigure(0, weight=1)

        container = ttk.Frame(self.splash_frame)
        container.grid(row=0, column=0)

        ttk.Label(container, text="Cloud Storage",
                  font=('Segoe UI', 32, 'bold'),
                  foreground='#ffffff').grid(row=0, column=0, pady=10)
        ttk.Label(container, text="Secure File Sharing",
                  font=('Segoe UI', 14),
                  foreground='#888888').grid(row=1, column=0, pady=5)

        self.loading_bar = ttk.Progressbar(container,
                                           mode='indeterminate',
                                           length=200,
                                           style='TProgressbar')
        self.loading_bar.grid(row=2, column=0, pady=30)
        self.loading_bar.start(15)

        self.master.after(2500, self.transition_to_login)

    def transition_to_login(self):
        """
            Handles the transition from the splash screen to the login frame.
            Stops the loading animation, hides the splash screen, and displays the login frame.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        self.loading_bar.stop()
        self.splash_frame.grid_remove()
        self.login_frame.place(relx=0.5, rely=0.5, anchor='center')
        self.master.focus_force()

    def create_login_frame(self):
        """
            Creates the user interface for login and registration.
            Includes entry fields for username and password, and buttons for login and register.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        self.login_frame = ttk.Frame(self.master, style='TFrame')

        container = ttk.Frame(self.login_frame)
        container.pack(pady=30, padx=50)

        container.grid_columnconfigure(0, minsize=100)
        container.grid_columnconfigure(1, weight=1)

        ttk.Label(container, text="Username:", font=('Segoe UI', 13), anchor='e').grid(row=0, column=0, padx=5,
                                                                                       sticky='e')
        self.ent_username = ttk.Entry(container, style='TEntry', font=('Segoe UI', 12))
        self.ent_username.grid(row=0, column=1, padx=5, pady=10, sticky='ew')

        ttk.Label(container, text="Password:", font=('Segoe UI', 13), anchor='e').grid(row=1, column=0, padx=5,
                                                                                       sticky='e')
        self.ent_password = ttk.Entry(container, show='*', style='TEntry', font=('Segoe UI', 12))
        self.ent_password.grid(row=1, column=1, padx=5, pady=10, sticky='ew')

        btn_container = ttk.Frame(container)
        btn_container.grid(row=2, column=0, columnspan=2, pady=25)
        ttk.Button(btn_container, text="Login", command=self.login, width=14).pack(side='left', padx=8)
        ttk.Button(btn_container, text="Register", command=self.register, width=14).pack(side='left', padx=8)

    def create_main_interface(self):
        """
            Creates the main application interface displayed after successful login.
            Includes file lists, permission management, and action buttons (upload, download, etc.).
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        self.main_frame = ttk.Frame(self.master)
        self.main_frame.grid(row=0, column=0, sticky='nsew')

        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1, uniform='cols')
        self.main_frame.grid_columnconfigure(1, weight=1, uniform='cols')

        self.create_file_lists()
        self.create_permissions_section()

        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=3, column=1, sticky='se', padx=25, pady=25)

        ttk.Button(button_frame, text="View File", command=self.view_file).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Upload File", command=self.upload_new).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Download File", command=self.download_file).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Edit File", command=self.edit_file).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Rename File", command=self.rename_file).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Delete File", command=self.delete_file).pack(side='left', padx=6)

        self.refresh_file_lists()
        self.start_auto_refresh()

    def create_file_lists(self):
        """
            Creates and configures the listbox widgets for displaying 'Your Files' (owned) and 'Shared Files'.
            Includes scrollbars and binds selection events.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        owned_frame = ttk.Frame(self.main_frame)
        owned_frame.grid(row=1, column=0, padx=(25, 10), pady=10, sticky='nsew')
        ttk.Label(owned_frame, text="Your Files", font=('Segoe UI', 14, 'bold')).pack()
        self.list_owned = tk.Listbox(owned_frame, bg='#333333', fg='white',
                                     font=('Segoe UI', 12), selectbackground='#4a4a4a')
        self.list_owned.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_owned = ttk.Scrollbar(owned_frame, orient=tk.VERTICAL, command=self.list_owned.yview)
        scroll_owned.pack(side=tk.RIGHT, fill=tk.Y)
        self.list_owned.config(yscrollcommand=scroll_owned.set)
        self.list_owned.bind('<<ListboxSelect>>', self.on_select_owned)

        shared_frame = ttk.Frame(self.main_frame)
        shared_frame.grid(row=1, column=1, padx=(10, 25), pady=10, sticky='nsew')
        ttk.Label(shared_frame, text="Shared Files", font=('Segoe UI', 14, 'bold')).pack()
        self.list_shared = tk.Listbox(shared_frame, bg='#333333', fg='white',
                                      font=('Segoe UI', 12), selectbackground='#4a4a4a')
        self.list_shared.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_shared = ttk.Scrollbar(shared_frame, orient=tk.VERTICAL, command=self.list_shared.yview)
        scroll_shared.pack(side=tk.RIGHT, fill=tk.Y)
        self.list_shared.config(yscrollcommand=scroll_shared.set)
        self.list_shared.bind('<<ListboxSelect>>', self.on_select_shared)

    def create_permissions_section(self):
        """
            Creates the UI section for managing file permissions.
            Includes an entry for target username and buttons to add/remove read/edit permissions.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        perm_frame = ttk.Frame(self.main_frame)
        perm_frame.grid(row=3, column=0, padx=25, pady=25, sticky='w')

        ttk.Label(perm_frame, text="Manage Permissions", font=('Segoe UI', 12, 'bold')).grid(row=0, column=0,
                                                                                             columnspan=4, pady=10)

        ttk.Label(perm_frame, text="Username:", font=('Segoe UI', 11)).grid(row=1, column=0, padx=5)
        self.ent_target = ttk.Entry(perm_frame, width=25, font=('Segoe UI', 11))
        self.ent_target.grid(row=1, column=1, padx=5)

        ttk.Button(perm_frame, text="Add Read", command=lambda: self.change_perm(True, 'read')).grid(row=2, column=0,
                                                                                                     pady=8)
        ttk.Button(perm_frame, text="Remove Read", command=lambda: self.change_perm(False, 'read')).grid(row=2,
                                                                                                         column=1,
                                                                                                         pady=8)
        ttk.Button(perm_frame, text="Add Edit", command=lambda: self.change_perm(True, 'edit')).grid(row=3, column=0,
                                                                                                     pady=8)
        ttk.Button(perm_frame, text="Remove Edit", command=lambda: self.change_perm(False, 'edit')).grid(row=3,
                                                                                                         column=1,
                                                                                                         pady=8)

    def start_auto_refresh(self):
        """
            Starts a recurring task to automatically refresh the file lists every 5 seconds.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        self.refresh_file_lists()
        self.master.after(5000, self.start_auto_refresh)

    def refresh_file_lists(self):
        """
            Refreshes the content of the 'owned' and 'shared' file listboxes.
            It fetches the latest file lists from the server and updates the UI,
            attempting to preserve any existing selections.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        selected_owned_indices = self.list_owned.curselection()
        selected_owned_values = [self.list_owned.get(i) for i in selected_owned_indices]

        selected_shared_indices = self.list_shared.curselection()
        selected_shared_values_raw = [self.list_shared.get(i) for i in selected_shared_indices]
        selected_shared_filenames = [entry.rsplit(' (', 1)[0] for entry in selected_shared_values_raw if ' (' in entry]

        success, owned, shared = self.client.list_files()
        if not success:
            return

        current_owned = list(self.list_owned.get(0, tk.END))
        if current_owned != owned:
            self.list_owned.delete(0, tk.END)
            for fname in owned:
                self.list_owned.insert(tk.END, fname)
            for fname_selected in selected_owned_values:
                try:
                    idx = owned.index(fname_selected)
                    self.list_owned.selection_set(idx)
                except ValueError:
                    pass

        current_shared_raw = list(self.list_shared.get(0, tk.END))
        new_shared_display = [f"{doc['filename']} ({doc['perm']})" for doc in shared]
        if current_shared_raw != new_shared_display:
            self.list_shared.delete(0, tk.END)
            for entry in new_shared_display:
                self.list_shared.insert(tk.END, entry)
            for fname_selected in selected_shared_filenames:
                for idx, entry_display in enumerate(new_shared_display):
                    if entry_display.startswith(fname_selected + ' ('):
                        self.list_shared.selection_set(idx)
                        break

    def register(self):
        """
            Handles the user registration process.
            Retrieves username and password from input fields, calls client's register method,
            and shows success/error messages. Automatically attempts to log in upon successful registration.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        username = self.ent_username.get()
        password = self.ent_password.get()
        success, message = self.client.register(username, password)
        if success:
            messagebox.showinfo("Success", message)
            self.login()
        else:
            messagebox.showerror("Error", message)

    def login(self):
        """
            Handles the user login process.
            Retrieves username and password, calls client's login method.
            If successful, hides login frame and shows main interface. Otherwise, shows error.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        username = self.ent_username.get()
        password = self.ent_password.get()
        success, message = self.client.login(username, password)
        if success:
            self.login_frame.place_forget()
            self.create_main_interface()
        else:
            messagebox.showerror("Error", message)

    def on_select_owned(self, event=None):
        """
        Handles selection events in the 'owned files' listbox.
        Clears any selection in the 'shared files' listbox to ensure only one
        item is selected across both lists at any time.
        :param self: The instance of the CloudClientGUI.
        :param event: The event that triggered this callback (optional).
        :return: None
        """
        self.list_shared.selection_clear(0, tk.END)

    def on_select_shared(self, event=None):
        """
        Handles selection events in the 'shared files' listbox.
        Clears any selection in the 'owned files' listbox to ensure only one
        item is selected across both lists at any time.
        :param self: The instance of the CloudClientGUI.
        :param event: The event that triggered this callback (optional).
        :return: None
        """
        self.list_owned.selection_clear(0, tk.END)

    def upload_new(self):
        """
            Handles the action of uploading a new file.
            Prompts the user to select a file using a file dialog, then calls the client's
            upload_file method. Shows success/error messages and refreshes file lists.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        success, message = self.client.upload_file(filepath)
        if not success:
            messagebox.showerror("Error", message)
        self.refresh_file_lists()

    def download_file(self):
        """
            Handles the action of downloading a selected file.
            Determines the selected file from either listbox, prompts for a save location,
            then calls the client's download_file method. Shows success/error messages.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        selected_owned = self.list_owned.curselection()
        selected_shared = self.list_shared.curselection()

        if not selected_owned and not selected_shared:
            messagebox.showwarning("Warning", "Please select a file to download")
            return

        if selected_owned:
            filename = self.list_owned.get(selected_owned[0])
        else:
            entry = self.list_shared.get(selected_shared[0])
            filename = entry.rsplit(' (', 1)[0]

        save_path = filedialog.asksaveasfilename(
            initialfile=filename,
            defaultextension=".*",
            filetypes=[("All files", "*.*")]
        )
        if not save_path:
            return

        success, message = self.client.download_file(filename, save_path)
        if success:
            messagebox.showinfo("Success", f"File '{filename}' downloaded successfully to {save_path}")
        else:
            messagebox.showerror("Error", message)

    def edit_file(self):
        """
        Handles the process of editing a file.
        This allows a user with edit permissions to replace a file on the server
        with a new local file. It can also handle renaming the file simultaneously
        if the new local file has a different name.
        :param self: The instance of the CloudClientGUI.
        :return: None
        """
        selected = self.list_owned.curselection() or self.list_shared.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a file to edit")
            return

        is_owned = bool(self.list_owned.curselection())
        if is_owned:
            old_filename = self.list_owned.get(selected[0])
        else:
            entry = self.list_shared.get(selected[0])
            old_filename = entry.rsplit(' (', 1)[0]
            if not entry.endswith('(edit)'):
                messagebox.showerror("Error", "You don't have edit permission for this file")
                return

        updated_filepath = filedialog.askopenfilename(title="Select updated file to upload as edit")
        if not updated_filepath:
            return

        new_filename = os.path.basename(updated_filepath)

        success, message = self.client.upload_file(updated_filepath, is_edit=True, is_owned=is_owned,
                                                   old_filename=old_filename, new_filename=new_filename)
        if not success:
            messagebox.showerror("Error", message)

        self.refresh_file_lists()
        self.list_owned.selection_clear(0, tk.END)
        self.list_shared.selection_clear(0, tk.END)

    def delete_file(self):
        """
            Handles deleting a selected file owned by the user.
            Confirms deletion with user, then calls client's delete_file method.
            Shows success/error messages and refreshes file lists. Only works for owned files.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        selected = self.list_owned.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a file from 'Your Files' to delete.")
            return

        filename = self.list_owned.get(selected[0])
        if not messagebox.askyesno("Confirm Delete",
                                   f"Are you sure you want to delete '{filename}'? This action cannot be undone."):
            return

        success, message = self.client.delete_file(filename)
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)
        self.refresh_file_lists()

    def rename_file(self):
        """
            Handles renaming a selected file owned by the user.
            Prompts for new filename using a dialog, then calls client's rename_file method.
            Shows success/error messages and refreshes file lists. Only works for owned files.
            :param self: The instance of CloudClientGUI.
            :return: None
        """
        selected = self.list_owned.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a file from 'Your Files' to rename.")
            return

        old_filename = self.list_owned.get(selected[0])
        new_filename = simpledialog.askstring("Rename File", "Enter new filename:", initialvalue=old_filename)

        if not new_filename or new_filename == old_filename:
            return

        success, message = self.client.rename_file(old_filename, new_filename)
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)
        self.refresh_file_lists()

    def change_perm(self, add: bool, perm: str):
        """
            Handles adding or removing a permission (read/edit) for a target user on a selected owned file.
            Retrieves filename, target user, then calls client's change_permission method.
            Shows success/error messages and refreshes file lists.
            :param self: The instance of CloudClientGUI.
            :param add: bool: True to add permission, False to remove.
            :param perm: str: The permission type ('read' or 'edit').
            :return: None
        """
        selected = self.list_owned.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Please select one of 'Your Files' to modify its permissions.")
            return

        filename = self.list_owned.get(selected[0])
        target_user = self.ent_target.get()
        if not target_user:
            messagebox.showwarning("Warning", "Please enter a target username for permission changes.")
            return
        if target_user == self.client.user.get("username"):
            messagebox.showwarning("Warning", "You cannot change your own permissions.")
            return

        success, message = self.client.change_permission(filename, target_user, perm, add)
        if success:
            action_str = "added" if add else "removed"
            perm_str = "read" if perm == "read" else "edit"
            messagebox.showinfo("Success",
                                f"Permission to {perm_str} '{filename}' {action_str} for user '{target_user}'.")
        else:
            messagebox.showerror("Error", message)
        self.refresh_file_lists()

    def view_file(self):
        """
        Orchestrates the process of viewing a selected file in a new window.
        This function determines the selected file, creates a new window, and
        then dispatches the loading and display logic to helper methods based
        on the file's extension, ensuring the GUI remains responsive.
        :param self: The instance of the CloudClientGUI.
        :return: None
        """
        selected = self.list_owned.curselection() or self.list_shared.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a file to view")
            return

        if self.list_owned.curselection():
            filename = self.list_owned.get(selected[0])
        else:
            entry = self.list_shared.get(selected[0])
            filename = entry.rsplit(' (', 1)[0]

        _, ext = os.path.splitext(filename.lower())

        view_window = tk.Toplevel(self.master)
        view_window.title(f"Viewing: {filename}")
        view_window.geometry("800x600")
        view_window.configure(bg='#0a0a0a')

        view_window.grid_rowconfigure(1, weight=1)
        view_window.grid_columnconfigure(0, weight=1)

        status_label = ttk.Label(view_window, text="Requesting file...", font=('Segoe UI', 10))
        status_label.grid(row=0, column=0, pady=5, sticky='ew')

        def load_and_display():
            self.client.send_msg('view', filename)
            status, filesize_str = self.client.recv_msg(2)

            if status != 'ready':
                message = filesize_str
                if "file is being edited" in str(message).lower():
                    status_label.config(text="File is being edited. Please try again later.")
                    messagebox.showwarning("Warning", "File is being edited. Please try again later.")
                else:
                    status_label.config(text=f"Error: {message}")
                    messagebox.showerror("Error", message)
                view_window.destroy()
                return

            try:
                filesize = int(filesize_str)
            except ValueError:
                messagebox.showerror("Error", "Invalid filesize received from server.")
                view_window.destroy()
                return

            status_label.config(text="Loading file...")
            view_window.update_idletasks()

            try:
                if ext == '.pdf':
                    self.display_pdf_from_stream(view_window, status_label, filesize)
                else:
                    self.display_data_from_memory(view_window, status_label, filesize, ext)
            except Exception as e:
                status_label.config(text=f"Error: {str(e)}")
                messagebox.showerror("Error", str(e))
                view_window.destroy()

        view_window.after(100, load_and_display)

    def display_pdf_from_stream(self, view_window, status_label, filesize):
        """
        Handles the memory-efficient display of a PDF file by streaming.
        Receives PDF data chunk-by-chunk and writes it directly to a temporary
        file on disk. Once complete, it uses the fitz library to render the
        pages from the temp file onto a Tkinter canvas with navigation.
        :param self: The instance of the CloudClientGUI.
        :param view_window: The Toplevel window to display the PDF in.
        :param status_label: The label widget for status updates.
        :param filesize: The total size of the incoming file data.
        :return: None
        """
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
                temp_path = temp_file.name
                remaining = filesize
                while remaining > 0:
                    chunk = self.client.sock.recv(min(4096, remaining))
                    if not chunk:
                        raise IOError("Connection lost while receiving PDF data.")
                    temp_file.write(chunk)
                    remaining -= len(chunk)

            final_status, final_message = self.client.recv_msg(2)
            if final_status != 'ok':
                raise IOError(f"Server reported an error after send: {final_message}")

            pdf_container = ttk.Frame(view_window)
            pdf_container.grid(row=1, column=0, sticky='nsew', padx=10, pady=10)
            pdf_container.grid_rowconfigure(0, weight=1)
            pdf_container.grid_columnconfigure(0, weight=1)
            canvas = tk.Canvas(pdf_container, bg='#1f1f1f')
            scrollbar_y = ttk.Scrollbar(pdf_container, orient='vertical', command=canvas.yview)
            scrollbar_x = ttk.Scrollbar(pdf_container, orient='horizontal', command=canvas.xview)
            canvas.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
            canvas.grid(row=0, column=0, sticky='nsew')
            scrollbar_y.grid(row=0, column=1, sticky='ns')
            scrollbar_x.grid(row=1, column=0, sticky='ew')
            pdf_frame = ttk.Frame(canvas)
            canvas.create_window((0, 0), window=pdf_frame, anchor='nw')
            doc = fitz.open(temp_path)
            current_page = 0
            page_images = []

            nav_frame = ttk.Frame(view_window)
            nav_frame.grid(row=2, column=0, pady=5)

            page_label_ref = [None]

            def display_page(page_num):
                nonlocal current_page
                if not (0 <= page_num < len(doc)):
                    return
                if page_label_ref[0]:
                    page_label_ref[0].destroy()

                current_page = page_num
                page = doc[current_page]
                pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                photo = ImageTk.PhotoImage(img)
                page_images.append(photo)

                page_label = ttk.Label(pdf_frame, image=photo)
                page_label.grid(row=0, column=0, padx=10, pady=10)
                page_label_ref[0] = page_label

                pdf_frame.update_idletasks()
                canvas.configure(scrollregion=canvas.bbox("all"))
                status_label.config(text=f"Page {current_page + 1} of {len(doc)}")

                prev_button.config(state='normal' if current_page > 0 else 'disabled')
                next_button.config(state='normal' if current_page < len(doc) - 1 else 'disabled')

            def on_window_close():
                try:
                    doc.close()
                    os.unlink(temp_path)
                except Exception:
                    pass
                view_window.destroy()

            prev_button = ttk.Button(nav_frame, text="Previous", command=lambda: display_page(current_page - 1))
            prev_button.grid(row=0, column=0, padx=5)
            next_button = ttk.Button(nav_frame, text="Next", command=lambda: display_page(current_page + 1))
            next_button.grid(row=0, column=1, padx=5)

            display_page(0)
            view_window.protocol("WM_DELETE_WINDOW", on_window_close)

        except Exception as e:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
            raise e

    def display_data_from_memory(self, view_window, status_label, filesize, ext):
        """
        Handles the display of non-PDF files (images, text) by loading them
        into a memory variable. It receives the entire file content into a
        bytes object and then uses the appropriate library (PIL or Tkinter)
        to render it.
        :param self: The instance of the CloudClientGUI.
        :param view_window: The Toplevel window to display the content in.
        :param status_label: The label widget for status updates.
        :param filesize: The total size of the incoming file data.
        :param ext: The file extension to determine how to display the data.
        :return: None
        """
        data = b''
        remaining = filesize
        while remaining > 0:
            chunk = self.client.sock.recv(min(4096, remaining))
            if not chunk:
                raise IOError("Connection lost while receiving file data.")
            data += chunk
            remaining -= len(chunk)

        final_status, final_message = self.client.recv_msg(2)
        if final_status != 'ok':
            raise IOError(f"Server reported an error after send: {final_message}")

        close_button = ttk.Button(view_window, text="Close", command=view_window.destroy)
        close_button.grid(row=3, column=0, pady=10)

        if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
            try:
                image = Image.open(io.BytesIO(data))
                max_width, max_height = 780, 500
                if image.width > max_width or image.height > max_height:
                    ratio = min(max_width / image.width, max_height / image.height)
                    image = image.resize((int(image.width * ratio), int(image.height * ratio)),
                                         Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(image)
                image_label = ttk.Label(view_window, image=photo)
                image_label.image = photo
                image_label.grid(row=1, column=0, padx=10, pady=10, sticky='nsew')
                status_label.config(text="Image loaded successfully")
            except Exception as e:
                raise RuntimeError(f"Could not display image: {e}")
        else:
            try:
                text_container = ttk.Frame(view_window)
                text_container.grid(row=1, column=0, sticky='nsew', padx=10, pady=10)
                text_container.grid_rowconfigure(0, weight=1)
                text_container.grid_columnconfigure(0, weight=1)
                text_widget = tk.Text(text_container, wrap=tk.WORD, bg='#1f1f1f', fg='white', font=('Consolas', 12),
                                      padx=10, pady=10)
                scrollbar = ttk.Scrollbar(text_container, orient=tk.VERTICAL, command=text_widget.yview)
                text_widget.configure(yscrollcommand=scrollbar.set)
                text_widget.grid(row=0, column=0, sticky='nsew')
                scrollbar.grid(row=0, column=1, sticky='ns')
                try:
                    content = data.decode('utf-8')
                except UnicodeDecodeError:
                    content = "[Binary file - cannot display content]"
                text_widget.insert('1.0', content)
                text_widget.config(state='disabled')
                status_label.config(text="File loaded successfully")
            except Exception as e:
                raise RuntimeError(f"Could not display text: {e}")


if __name__ == '__main__':
    root = tk.Tk()
    app = CloudClientGUI(root)
    root.mainloop()
