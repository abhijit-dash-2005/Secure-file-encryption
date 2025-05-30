
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

KEY_FILE = "secret.key"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        data = file.read()
    encrypted = fernet.encrypt(data)
    with open(file_path + ".enc", "wb") as file:
        file.write(encrypted)
    messagebox.showinfo("Success", f"File encrypted: {file_path}.enc")

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        encrypted = file.read()
    try:
        decrypted = fernet.decrypt(encrypted)
        original_path = file_path.replace(".enc", "")
        with open(original_path, "wb") as file:
            file.write(decrypted)
        messagebox.showinfo("Success", f"File decrypted: {original_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def choose_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        key = load_key()
        encrypt_file(file_path, key)

def choose_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path and file_path.endswith(".enc"):
        key = load_key()
        decrypt_file(file_path, key)
    else:
        messagebox.showerror("Error", "Please select a valid .enc file to decrypt.")

# GUI
root = tk.Tk()
root.title("Secure File Encryptor/Decryptor")

tk.Label(root, text="Secure File Encryption & Decryption", font=("Arial", 14)).pack(pady=10)

tk.Button(root, text="Encrypt File", command=choose_encrypt, width=20).pack(pady=5)
tk.Button(root, text="Decrypt File", command=choose_decrypt, width=20).pack(pady=5)

root.mainloop()
