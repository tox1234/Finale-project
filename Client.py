# client_gui.py
import socket
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import os

# --- Configuration ---
HOST = 'localhost'
PORT = 9009


class CloudClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("Cloud Client")
        master.geometry("1024x768")
        master.configure(bg='#0a0a0a')

        # Configure grid layout
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)

        # Initialize socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
        except Exception as e:
            messagebox.showerror("Connection Error", f"Cannot connect to server: {e}")
            master.destroy()
            return

        self.user = None
        self.setup_styles()
        self.create_splash_screen()
        self.create_login_frame()

    def setup_styles(self):
        """Configure modern dark theme styles"""
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Color scheme
        bg_color = '#0a0a0a'
        entry_bg = '#1f1f1f'
        button_bg = '#2a2a2a'
        text_color = '#ffffff'
        accent_color = '#404040'

        # Configure styles
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
        """Create animated splash screen"""
        self.splash_frame = ttk.Frame(self.master)
        self.splash_frame.grid(row=0, column=0, sticky='nsew')

        # Center content
        self.splash_frame.grid_rowconfigure(0, weight=1)
        self.splash_frame.grid_columnconfigure(0, weight=1)

        container = ttk.Frame(self.splash_frame)
        container.grid(row=0, column=0)

        # Animated text elements
        ttk.Label(container, text="Ido's Cloud Storage",
                  font=('Segoe UI', 32, 'bold'),
                  foreground='#ffffff').grid(row=0, column=0, pady=10)
        ttk.Label(container, text="Made by Ido Shema",
                  font=('Segoe UI', 14),
                  foreground='#888888').grid(row=1, column=0, pady=5)

        # Loading animation
        self.loading_bar = ttk.Progressbar(container,
                                           mode='indeterminate',
                                           length=200,
                                           style='TProgressbar')
        self.loading_bar.grid(row=2, column=0, pady=30)
        self.loading_bar.start(15)

        # Transition to login after 2.5 seconds
        self.master.after(2500, self.transition_to_login)

    def transition_to_login(self):
        """Animate transition from splash to login"""
        self.loading_bar.stop()
        self.splash_frame.grid_remove()
        self.login_frame.place(relx=0.5, rely=0.5, anchor='center')
        self.master.focus_force()

    def create_login_frame(self):
        """Create modern centered login/registration frame with aligned entries"""
        self.login_frame = ttk.Frame(self.master, style='TFrame')

        # Main container
        container = ttk.Frame(self.login_frame)
        container.pack(pady=30, padx=50)

        # Configure grid columns
        container.grid_columnconfigure(0, minsize=100)  # Label column
        container.grid_columnconfigure(1, weight=1)  # Entry column

        # Username Section
        ttk.Label(container, text="Username:", font=('Segoe UI', 13), anchor='e').grid(row=0, column=0, padx=5,
                                                                                       sticky='e')
        self.ent_username = ttk.Entry(container, style='TEntry', font=('Segoe UI', 12))
        self.ent_username.grid(row=0, column=1, padx=5, pady=10, sticky='ew')

        # Password Section
        ttk.Label(container, text="Password:", font=('Segoe UI', 13), anchor='e').grid(row=1, column=0, padx=5,
                                                                                       sticky='e')
        self.ent_password = ttk.Entry(container, show='*', style='TEntry', font=('Segoe UI', 12))
        self.ent_password.grid(row=1, column=1, padx=5, pady=10, sticky='ew')

        # Buttons
        btn_container = ttk.Frame(container)
        btn_container.grid(row=2, column=0, columnspan=2, pady=25)
        ttk.Button(btn_container, text="Login", command=self.login, width=14).pack(side='left', padx=8)
        ttk.Button(btn_container, text="Register", command=self.register, width=14).pack(side='left', padx=8)

    def create_main_interface(self):
        """Create main application interface"""
        self.main_frame = ttk.Frame(self.master)
        self.main_frame.grid(row=0, column=0, sticky='nsew')

        # Configure grid layout
        self.main_frame.grid_rowconfigure(1, weight=1)  # File lists row
        self.main_frame.grid_columnconfigure(0, weight=1, uniform='cols')
        self.main_frame.grid_columnconfigure(1, weight=1, uniform='cols')

        # File lists
        self.create_file_lists()
        self.create_permissions_section()

        # Bottom Right Buttons
        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=3, column=1, sticky='se', padx=25, pady=25)

        ttk.Button(button_frame, text="Upload File", command=self.upload_new).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Download File", command=self.download_file).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Edit File", command=self.edit_file).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Rename File", command=self.rename_file).pack(side='left', padx=6)
        ttk.Button(button_frame, text="Delete File", command=self.delete_file).pack(side='left', padx=6)

        self.refresh_file_lists()
        self.start_auto_refresh()

    def create_file_lists(self):
        """Create file list views with equal size"""
        # Owned files
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

        # Shared files
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
        """Create permissions management section at bottom left"""
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
        """Start automatic refresh of file lists"""
        self.refresh_file_lists()
        self.master.after(5000, self.start_auto_refresh)

    def refresh_file_lists(self):
        """Refresh file lists while preserving selections"""
        # Store current selections
        selected_owned = [self.list_owned.get(i) for i in self.list_owned.curselection()]

        # FIX 2: Properly parse filenames with spaces from shared list
        selected_shared = []
        for i in self.list_shared.curselection():
            entry = self.list_shared.get(i)
            if ' (' in entry:
                filename = entry.rsplit(' (', 1)[0]
                selected_shared.append(filename)

        # Get updated file lists
        self.send_json({"action": "list_files"})
        resp = self.recv_json()
        if not resp or resp.get('status') != 'ok':
            return

        # Update owned files
        current_owned = self.list_owned.get(0, tk.END)
        new_owned = resp.get('owned', [])
        if set(current_owned) != set(new_owned):
            self.list_owned.delete(0, tk.END)
            for fname in new_owned:
                self.list_owned.insert(tk.END, fname)
            for idx, fname in enumerate(new_owned):
                if fname in selected_owned:
                    self.list_owned.selection_set(idx)

        # Update shared files
        # FIX 2: Handle filenames with spaces in shared list
        current_shared = []
        for entry in self.list_shared.get(0, tk.END):
            if ' (' in entry:
                filename = entry.rsplit(' (', 1)[0]
                current_shared.append(filename)
            else:
                current_shared.append(entry)

        new_shared = [f['filename'] for f in resp.get('shared', [])]

        if set(current_shared) != set(new_shared):
            self.list_shared.delete(0, tk.END)
            for item in resp.get('shared', []):
                entry = f"{item['filename']} ({item['perm']})"
                self.list_shared.insert(tk.END, entry)
            for idx, item in enumerate(resp.get('shared', [])):
                if item['filename'] in selected_shared:
                    self.list_shared.selection_set(idx)

    def send_json(self, data):
        msg = json.dumps(data) + '\n'
        self.sock.sendall(msg.encode('utf-8'))

    def recv_json(self):
        buffer = b''
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            buffer += chunk
            if b'\n' in buffer:
                line, _ = buffer.split(b'\n', 1)
                try:
                    return json.loads(line.decode('utf-8'))
                except json.JSONDecodeError:
                    return None

    def register(self):
        username = self.ent_username.get().strip()
        password = self.ent_password.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Enter both username and password.")
            return
        self.send_json({"action": "register", "username": username, "password": password})
        resp = self.recv_json()
        if resp.get('status') == 'ok':
            messagebox.showinfo("Success", resp.get('message'))
        else:
            messagebox.showerror("Error", resp.get('message'))

    def login(self):
        username = self.ent_username.get().strip()
        password = self.ent_password.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Enter both username and password.")
            return
        self.send_json({"action": "login", "username": username, "password": password})
        resp = self.recv_json()
        if resp.get('status') == 'ok':
            self.user = username
            self.login_frame.place_forget()
            self.create_main_interface()
        else:
            messagebox.showerror("Error", resp.get('message'))

    def on_select_owned(self, event):
        self.list_shared.selection_clear(0, tk.END)

    def on_select_shared(self, event):
        self.list_owned.selection_clear(0, tk.END)

    def upload_new(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        filename = os.path.basename(path)
        filesize = os.path.getsize(path)
        self.send_json({"action": "upload", "filename": filename, "filesize": filesize})
        resp = self.recv_json()
        if resp.get('status') != 'ready':
            messagebox.showerror("Error", resp.get('message', 'Upload failed.'))
            return
        with open(path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                self.sock.sendall(data)
        result = self.recv_json()
        if result.get('status') == 'ok':
            messagebox.showinfo("Success", result.get('message'))
            self.refresh_file_lists()
        else:
            messagebox.showerror("Error", result.get('message'))

    def download_file(self):
        sel_owned = self.list_owned.curselection()
        sel_shared = self.list_shared.curselection()
        if sel_owned:
            filename = self.list_owned.get(sel_owned[0])
            print(filename)
        elif sel_shared:
            entry = self.list_shared.get(sel_shared[0])
            if ' (' in entry:
                filename = entry.rsplit(' (', 1)[0]
            else:
                filename = entry
        else:
            messagebox.showerror("Error", "No file selected.")
            return
        save_path = filedialog.asksaveasfilename(defaultextension="", initialfile=filename)
        if not save_path:
            return
        self.send_json({"action": "download", "filename": filename})
        resp = self.recv_json()
        if resp.get('status') != 'ready':
            messagebox.showerror("Error", resp.get('message', 'Download failed.'))
            return
        filesize = resp.get('filesize')
        remaining = filesize
        try:
            with open(save_path, 'wb') as f:
                while remaining > 0:
                    chunk = self.sock.recv(min(4096, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")
            return
        final = self.recv_json()
        if final.get('status') == 'ok':
            messagebox.showinfo("Success", f"Downloaded '{filename}' successfully.")
        else:
            messagebox.showerror("Error", final.get('message'))

    def edit_file(self):
        sel_owned = self.list_owned.curselection()
        sel_shared = self.list_shared.curselection()
        if sel_owned:
            filename = self.list_owned.get(sel_owned[0])
        elif sel_shared:
            entry = self.list_shared.get(sel_shared[0])
            if ' (' in entry:
                filename = entry.rsplit(' (', 1)[0]
            else:
                filename = entry
        else:
            messagebox.showerror("Error", "No file selected.")
            return
        path = filedialog.askopenfilename(title=f"Select new version for {filename}")
        if not path:
            return
        filesize = os.path.getsize(path)
        self.send_json({"action": "upload", "filename": filename, "filesize": filesize})
        resp = self.recv_json()
        if resp.get('status') != 'ready':
            messagebox.showerror("Error", resp.get('message', 'Edit failed.'))
            return
        with open(path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                self.sock.sendall(data)
        result = self.recv_json()
        if result.get('status') == 'ok':
            messagebox.showinfo("Success", result.get('message'))
        else:
            messagebox.showerror("Error", result.get('message'))

    def delete_file(self):
        # Determine selected filename
        sel = self.list_owned.curselection()
        if not sel:
            messagebox.showerror("Error", "Select one of your files to delete.")
            return
        filename = self.list_owned.get(sel[0])
        if not messagebox.askyesno("Confirm Delete", f"Really delete '{filename}'?"):
            return
        self.send_json({"action":"delete", "filename": filename})
        resp = self.recv_json()
        if resp.get('status') == 'ok':
            messagebox.showinfo("Deleted", resp.get('message'))
            self.refresh_file_lists()
        else:
            messagebox.showerror("Error", resp.get('message'))

    def rename_file(self):
        # Determine selected filename (owned or shared)
        sel_owned = self.list_owned.curselection()
        sel_shared = self.list_shared.curselection()
        if sel_owned:
            old = self.list_owned.get(sel_owned[0])
        elif sel_shared:
            entry = self.list_shared.get(sel_shared[0])
            old = entry.split(' (',1)[0]
        else:
            messagebox.showerror("Error", "Select a file to rename.")
            return
        new = simpledialog.askstring("Rename File", f"New name for '{old}':")
        if not new:
            return
        self.send_json({"action":"rename","old_filename":old,"new_filename":new})
        resp = self.recv_json()
        if resp.get('status') == 'ok':
            messagebox.showinfo("Renamed", resp.get('message'))
            self.refresh_file_lists()
        else:
            messagebox.showerror("Error", resp.get('message'))

    def change_perm(self, add, perm):
        sel = self.list_owned.curselection()
        if not sel:
            messagebox.showerror("Error", "Select an owned file first.")
            return
        filename = self.list_owned.get(sel[0])
        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter the target username.")
            return
        action = "add_permission" if add else "remove_permission"
        self.send_json({
            "action": action, "file": filename,
            "target_user": target, "permission": perm
        })
        resp = self.recv_json()
        if resp.get('status') == 'ok':
            messagebox.showinfo("Success", resp.get('message'))
            self.ent_target.delete(0, tk.END)
        else:
            messagebox.showerror("Error", resp.get('message'))


if __name__ == '__main__':
    root = tk.Tk()
    app = CloudClientGUI(root)
    root.mainloop()
