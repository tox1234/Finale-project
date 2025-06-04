import os
import threading
from typing import Dict, Tuple


def sanitize_filename(filename: str) -> str:
    """
        Sanitizes a filename to prevent path traversal attacks.
        It returns only the base component of the filename.
        :param filename: str: The original filename string.
        :return: str: The sanitized filename (basename only).
    """
    return os.path.basename(filename)


def get_file_size(filepath: str) -> int:
    """
        Gets the size of a file in bytes if it exists.
        Returns 0 if the file does not exist or an error occurs.
        :param filepath: str: The path to the file.
        :return: int: The size of the file in bytes, or 0 on error/non-existence.
    """
    try:
        return os.path.getsize(filepath) if os.path.exists(filepath) else 0
    except OSError:  # More specific exception
        return 0


class FileManager:
    """
    Manages file operations for the server, including creating, reading,
    writing, deleting, and renaming files, with support for basic
    readers-writer locking to handle concurrent access.
    """

    def __init__(self, base_dir: str = 'server_files'):
        """
            Initializes the FileManager.
            Creates the base directory for storing files if it doesn't exist,
            and initializes the file locks dictionary.
            :param self: The instance of the FileManager.
            :param base_dir: str: The base directory where server files will be stored.
                                  Defaults to 'server_files'.
            :return: None
        """
        self.file_locks: Dict[str, Dict] = {}
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)
        self.clear_all_locks()

    def clear_all_locks(self):
        """
            Clears all existing file locks.
            This is typically used when the server starts to ensure a clean state,
            resetting any locks that might have been held.
            :param self: The instance of the FileManager.
            :return: None
        """
        self.file_locks.clear()

    def get_file_locks(self, filepath: str) -> Dict:
        """
            Retrieves or initializes the lock structure for a given file path.
            If locks for the filepath do not exist, they are created.
            The structure includes a readers count, a read lock, and a write lock.
            :param self: The instance of the FileManager.
            :param filepath: str: The path to the file for which locks are needed.
            :return: Dict: A dictionary containing 'readers' count, 'read_lock'
                           (threading.Lock), and 'write_lock' (threading.Lock).
        """
        if filepath not in self.file_locks:
            self.file_locks[filepath] = {
                'readers': 0,
                'read_lock': threading.Lock(),
                'write_lock': threading.Lock()
            }
        return self.file_locks[filepath]

    def get_file_path(self, filename: str, user_id: str) -> str:
        """
            Constructs the full, sanitized path for a file within a user-specific
            subdirectory. Creates the user's subdirectory if it doesn't exist.
            The filename is sanitized to prevent path traversal.
            :param self: The instance of the FileManager.
            :param filename: str: The name of the file (e.g., 'document.txt').
            :param user_id: str: The unique identifier for the user.
            :return: str: The full, safe path to the file on the server.
        """
        safe_filename = sanitize_filename(filename)
        file_subdir = os.path.join(self.base_dir, str(user_id))
        os.makedirs(file_subdir, exist_ok=True)
        path = os.path.join(file_subdir, safe_filename)
        print(f"[DEBUG] get_file_path: filename='{filename}', "
              f"sanitized='{safe_filename}', path='{path}'")
        return path

    def acquire_read_lock(self, filepath: str) -> None:
        """
            Acquires a read lock for the specified file path.
            This implements part of a readers-writer lock: multiple readers are
            allowed. The first reader acquires the write_lock to block writers.
            :param self: The instance of the FileManager.
            :param filepath: str: The path to the file to be read-locked.
            :return: None
        """
        locks = self.get_file_locks(filepath)
        print(f"[DEBUG] Trying to acquire read lock for {filepath}")
        locks['read_lock'].acquire()
        locks['readers'] += 1
        if locks['readers'] == 1:
            locks['write_lock'].acquire()
        locks['read_lock'].release()
        print(f"[DEBUG] Acquired read lock for {filepath} "
              f"(readers={locks['readers']})")

    def release_read_lock(self, filepath: str) -> None:
        """
            Releases a previously acquired read lock for the specified file path.
            If this is the last reader, it releases the write_lock to allow
            writers.
            :param self: The instance of the FileManager.
            :param filepath: str: The path to the file whose read lock is to be
                                  released.
            :return: None
        """
        locks = self.get_file_locks(filepath)
        locks['read_lock'].acquire()
        locks['readers'] -= 1
        if locks['readers'] == 0:
            locks['write_lock'].release()
        locks['read_lock'].release()
        print(f"[DEBUG] Released read lock for {filepath} "
              f"(readers={locks['readers']})")

    def acquire_write_lock(self, filepath: str) -> None:
        """
            Acquires a write lock for the specified file path.
            This lock is exclusive; it blocks if there are any active readers or
            if another writer holds the lock.
            :param self: The instance of the FileManager.
            :param filepath: str: The path to the file to be write-locked.
            :return: None
            :raises RuntimeError: If there are active readers or writers on the file.
        """
        locks = self.get_file_locks(filepath)
        if locks['readers'] > 0:
            print(f"[DEBUG] Failed to acquire write lock for {filepath} "
                  f"(readers present: {locks['readers']})")
            raise RuntimeError("File is being viewed by another user. Please try again later.")

        # Try to acquire the write lock with a timeout
        if not locks['write_lock'].acquire(timeout=0.1):
            print(f"[DEBUG] Failed to acquire write lock for {filepath} (write lock held)")
            raise RuntimeError("File is being edited by another user. Please try again later.")

        print(f"[DEBUG] Acquired write lock for {filepath}")

    def release_write_lock(self, filepath: str) -> None:
        """
            Releases a previously acquired write lock for the specified file path.
            :param self: The instance of the FileManager.
            :param filepath: str: The path to the file whose write lock is to be
                                  released.
            :return: None
        """
        locks = self.get_file_locks(filepath)
        if locks['write_lock'].locked():
            locks['write_lock'].release()
            print(f"[DEBUG] Released write lock for {filepath}")
        else:
            print(f"[DEBUG] Attempted to release an already unlocked write lock "
                  f"for {filepath}")

    def write_file(self, filepath: str, data: bytes) -> bool:
        """
            Writes data to a file at the specified path, using a write lock
            to ensure exclusive access during the write operation.
            :param self: The instance of the FileManager.
            :param filepath: str: The full path to the file to be written.
            :param data: bytes: The binary data to write to the file.
            :return: bool: True if the write operation was successful,
                           False otherwise.
        """
        lock_acquired_successfully = False
        try:
            self.acquire_write_lock(filepath)
            lock_acquired_successfully = True
            with open(filepath, 'wb') as f:
                f.write(data)
            return True
        except RuntimeError as e:  # Specifically for lock acquisition failure
            print(f"Could not acquire lock to write file {filepath}: {e}")
            return False
        except OSError as e:
            print(f"Error writing file {filepath}: {e}")
            return False
        finally:
            if lock_acquired_successfully:
                self.release_write_lock(filepath)

    def read_file(self, filepath: str) -> Tuple[bool, bytes]:
        """
            Reads data from a file at the specified path, using a read lock
            to allow concurrent reads while blocking writes.
            :param self: The instance of the FileManager.
            :param filepath: str: The full path to the file to be read.
            :return: Tuple[bool, bytes]: A tuple where the first element is True
                                         on success (False on failure), and the
                                         second element is the file's content as
                                         bytes (or b'' on failure).
        """
        lock_acquired_successfully = False
        try:
            self.acquire_read_lock(filepath)
            lock_acquired_successfully = True
            if not os.path.exists(filepath):  # Check existence after acquiring lock
                print(f"File not found for reading: {filepath}")
                return False, b''
            with open(filepath, 'rb') as f:
                data = f.read()
            return True, data
        except OSError as e:
            print(f"Error reading file {filepath}: {e}")
            return False, b''
        finally:
            if lock_acquired_successfully:
                self.release_read_lock(filepath)

    def delete_file(self, filepath: str) -> bool:
        """
            Deletes a file at the specified path, using a write lock to ensure
            exclusive access during the delete operation.
            :param self: The instance of the FileManager.
            :param filepath: str: The full path to the file to be deleted.
            :return: bool: True if the file was successfully deleted or did not
                           exist, False if an error occurred during deletion.
        """
        lock_acquired_successfully = False
        try:
            self.acquire_write_lock(filepath)
            lock_acquired_successfully = True
            if os.path.exists(filepath):
                os.remove(filepath)
            if filepath in self.file_locks:
                del self.file_locks[filepath]
            return True
        except RuntimeError as e:
            print(f"Could not acquire lock to delete file {filepath}: {e}")
            return False
        except OSError as e:
            print(f"Error deleting file {filepath}: {e}")
            return False
        finally:
            if lock_acquired_successfully:
                if filepath in self.file_locks:
                    self.release_write_lock(filepath)
                else:
                    print(f"[DEBUG] Write lock for deleted file {filepath} already removed.")

    def rename_file(self, old_path: str, new_path: str) -> bool:
        """
            Renames (moves) a file from an old path to a new path.
            It acquires write locks for both the old and new paths to ensure
            atomicity and prevent conflicts during the operation.
            :param self: The instance of the FileManager.
            :param old_path: str: The current full path of the file.
            :param new_path: str: The new desired full path for the file.
            :return: bool: True if the rename operation was successful,
                           False otherwise.
        """
        old_lock_acquired = False
        new_lock_acquired = False

        try:

            self.acquire_write_lock(old_path)
            old_lock_acquired = True
            self.acquire_write_lock(
                new_path)
            new_lock_acquired = True

            if not os.path.exists(old_path):
                print(f"Source file for rename does not exist: {old_path}")
                return False
            if os.path.exists(new_path):
                print(f"Target file for rename already exists: {new_path}")
                return False

            os.rename(old_path, new_path)

            if old_path in self.file_locks:
                self.file_locks[new_path] = self.file_locks.pop(old_path)
            else:
                self.get_file_locks(new_path)

            return True
        except RuntimeError as e:
            print(f"Could not acquire lock to rename {old_path} to {new_path}: {e}")
            return False
        except OSError as e:
            print(f"Error renaming file {old_path} to {new_path}: {e}")
            return False
        finally:
            if new_lock_acquired:
                self.release_write_lock(new_path)
            if old_lock_acquired:
                self.release_write_lock(old_path)
