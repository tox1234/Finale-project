"""
Author: Ido Shema
Last_updated: 05/05/2025
Description: database manager
"""
from pymongo import MongoClient, errors
import hashlib


def hash_password(password: str) -> str:
    """
        Hashes a password using SHA-256.
        The password is encoded to UTF-8 before hashing.
        :param password: str: The plain text password string to hash.
        :return: str: The hexadecimal representation of the SHA-256 hash.
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


class DatabaseManager:
    """
    Manages all interactions with the MongoDB database for the cloud storage
    service. This includes user authentication, file metadata storage,
    and permission management.
    """

    def __init__(self):
        """
            Initializes the DatabaseManager.
            Establishes a connection to the MongoDB server, selects the
            database and collections, and sets up necessary indexes.
            :param self: The instance of the DatabaseManager.
            :return: None
        """
        self.client = MongoClient('mongodb://localhost:27017/')
        self.db = self.client['cloud_storage']
        self.users_col = self.db['users']
        self.files_col = self.db['files']
        self._setup_indexes()

    def _setup_indexes(self):
        """
            Sets up necessary database indexes for collections.
            Ensures 'username' is unique in the users collection.
            Attempts to drop an old 'filename_1' index if it exists.
            :param self: The instance of the DatabaseManager.
            :return: None
        """
        self.users_col.create_index('username', unique=True)
        try:
            self.files_col.drop_index('filename_1')
        except errors.OperationFailure as e:
            if e.code == 27:
                print("Note: Index 'filename_1' not found, no need to drop.")
            else:
                print(f"Note: Could not drop filename_1 index (it may not exist or another issue): {e}")

    def register_user(self, username: str, password: str) -> tuple[bool, str]:
        """
            Registers a new user in the database.
            Checks for missing username/password and existing username.
            Stores the password as a SHA-256 hash.
            :param self: The instance of the DatabaseManager.
            :param username: str: The desired username for the new user.
            :param password: str: The plain text password for the new user.
            :return: tuple[bool, str]: A tuple (success_status, message).
                                       True if registration is successful.
        """
        if not username or not password:
            return False, "Missing username or password."
        if self.users_col.find_one({"username": username}):
            return False, "Username already exists."

        pwd_hash = hash_password(password)
        self.users_col.insert_one({
            "username": username,
            "password_hash": pwd_hash
        })
        return True, "Registered successfully."

    def authenticate_user(self, username: str, password: str) -> dict | None:
        """
            Authenticates a user based on username and password.
            Compares the hash of the provided password with the stored hash.
            :param self: The instance of the DatabaseManager.
            :param username: str: The username of the user to authenticate.
            :param password: str: The plain text password to verify.
            :return: dict | None: The user document (dictionary) if authentication
                                   is successful, otherwise None.
        """
        if not username or not password:
            return None
        user = self.users_col.find_one({"username": username})
        if not user or user['password_hash'] != hash_password(password):
            return None
        return user

    def get_user_files(self, user_id: str) -> tuple[list[str], list[dict]]:
        """
            Retrieves lists of files owned by and shared with a specific user.
            Owned files are returned as a list of filenames.
            Shared files include filename and the permission level ('read' or 'edit').
            :param self: The instance of the DatabaseManager.
            :param user_id: str: The unique identifier (_id) of the user.
            :return: tuple[list[str], list[dict]]: A tuple containing:
                     - A list of filenames owned by the user.
                     - A list of dictionaries for shared files, each with
                       'filename' and 'perm' keys.
        """
        owned_cursor = self.files_col.find({"owner_user_id": user_id})
        owned = [doc['filename'] for doc in owned_cursor]

        shared_query = {
            "owner_user_id": {"$ne": user_id},
            "$or": [
                {"allowed_read_user_ids": user_id},
                {"allowed_edit_user_ids": user_id}
            ]
        }
        shared_docs = self.files_col.find(shared_query)
        shared = []
        for doc in shared_docs:
            perm = "edit" if user_id in doc.get('allowed_edit_user_ids', []) \
                else "read"
            shared.append({"filename": doc['filename'], "perm": perm})

        return owned, shared

    def create_file(self, filename: str, filepath: str, owner_id: str):
        """
            Creates a new file document in the database.
            Initializes with empty lists for read/edit permissions.
            :param self: The instance of the DatabaseManager.
            :param filename: str: The name of the file.
            :param filepath: str: The server-side path where the file is stored.
            :param owner_id: str: The unique identifier (_id) of the file owner.
            :return: InsertOneResult: The result object from MongoDB's insert_one operation.
        """
        return self.files_col.insert_one({
            "filename": filename,
            "path": filepath,
            "owner_user_id": owner_id,
            "allowed_read_user_ids": [],
            "allowed_edit_user_ids": []
        })

    def get_file_doc(self, filename: str, user_id: str,
                     check_permissions: bool = True) -> dict | None:
        """
            Retrieves a file document by its filename.
            If check_permissions is True (default), it also ensures the user
            is either the owner or has read/edit permissions.
            If check_permissions is False, it only queries by filename.
            :param self: The instance of the DatabaseManager.
            :param filename: str: The name of the file to retrieve.
            :param user_id: str: The unique identifier (_id) of the user
                                 requesting the file.
            :param check_permissions: bool: Whether to check user permissions
                                           (default True).
            :return: dict | None: The file document (dictionary) if found and
                                   accessible (if checked), otherwise None.
        """
        query = {"filename": filename}
        if check_permissions:
            query["$or"] = [
                {"owner_user_id": user_id},
                {"allowed_read_user_ids": user_id},
                {"allowed_edit_user_ids": user_id}
            ]
        return self.files_col.find_one(query)

    def update_file_permissions(self, filename: str, owner_id: str,
                                target_user_id: str, permission_type: str,
                                add: bool = True) -> tuple[bool, str]:
        """
            Updates the permissions (read or edit) for a target user on a file.
            The operation is performed by the file's owner.
            :param self: The instance of the DatabaseManager.
            :param filename: str: The name of the file.
            :param owner_id: str: The _id of the file's owner.
            :param target_user_id: str: The _id of the user whose permissions
                                        are being modified.
            :param permission_type: str: The type of permission ('read' or 'edit').
            :param add: bool: True to add the permission (default), False to remove it.
            :return: tuple[bool, str]: (True, "Permission updated.") on success,
                                       (False, "File not found.") if the owner
                                       doesn't own such a file.
        """
        file_doc = self.files_col.find_one({
            "filename": filename,
            "owner_user_id": owner_id
        })
        if not file_doc:
            return False, "File not found or you are not the owner."

        field = f"allowed_{permission_type}_user_ids"
        update_operation = "$addToSet" if add else "$pull"

        self.files_col.update_one(
            {"_id": file_doc["_id"]},
            {update_operation: {field: target_user_id}}
        )
        return True, "Permission updated."

    def delete_file(self, filename: str, user_id: str) -> bool:
        """
            Deletes a file document from the database.
            The deletion is only successful if the user_id matches the
            owner_user_id of the file.
            :param self: The instance of the DatabaseManager.
            :param filename: str: The name of the file to delete.
            :param user_id: str: The _id of the user attempting to delete the file.
            :return: bool: True if the file document was successfully deleted,
                           False otherwise.
        """
        result = self.files_col.delete_one({
            "filename": filename,
            "owner_user_id": user_id
        })
        return result.deleted_count > 0

    def rename_file(self, old_filename: str, new_filename: str,
                    user_id: str, new_filepath: str) -> bool:
        """
            Renames a file document and updates its path in the database.
            The operation is only successful if user_id matches owner_user_id.
            :param self: The instance of the DatabaseManager.
            :param old_filename: str: The current name of the file.
            :param new_filename: str: The new desired name for the file.
            :param user_id: str: The _id of the user (owner) renaming the file.
            :param new_filepath: str: The new server-side path for the file.
            :return: bool: True if the file document was successfully updated,
                           False otherwise.
        """
        result = self.files_col.update_one(
            {"filename": old_filename, "owner_user_id": user_id},
            {"$set": {"filename": new_filename, "path": new_filepath}}
        )
        return result.modified_count > 0

    def get_user_by_username(self, username: str) -> dict | None:
        """
            Retrieves a user document from the database by username.
            :param self: The instance of the DatabaseManager.
            :param username: str: The username to search for.
            :return: dict | None: The user document (dictionary) if found,
                                   otherwise None.
        """
        return self.users_col.find_one({"username": username})
