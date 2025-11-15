import os
import random
import string
import base64
from tkinter import *
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

BG = "#000000"
PANEL_BG = "#0d1f0d"
ACCENT = "#00ff66"
ACCENT_DIM = "#00cc55"
FONT_MAIN = ("Consolas", 12)
FONT_HEADER = ("Consolas", 16, "bold")

def signup_user(username, password):
    if not os.path.exists("users.txt"):
        open("users.txt", "w").close()
    with open("users.txt", "r") as f:
        if any(line.startswith(username + ":") for line in f):
            return False
    with open("users.txt", "a") as f:
        f.write(f"{username}:{password}\n")
    return True

def validate_login(username, password):
    if not os.path.exists("users.txt"):
        return False
    with open("users.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line == f"{username}:{password}":
                return True
    return False

def get_all_users():
    if not os.path.exists("users.txt"):
        return []
    with open("users.txt", "r") as f:
        return [line.strip().split(":")[0] for line in f if ":" in line]

def generate_rsa_keypair(username, bits=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{username}_private.pem", "wb") as f:
        f.write(priv_pem)
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{username}_public.pem", "wb") as f:
        f.write(pub_pem)
    return private_key, public_key

def load_public_key(username):
    path = f"{username}_public.pem"
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        pub_pem = f.read()
    return serialization.load_pem_public_key(pub_pem)

def load_private_key(username):
    path = f"{username}_private.pem"
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        priv_pem = f.read()
    return serialization.load_pem_private_key(priv_pem, password=None)

def encrypt_for_user(recipient, message):
    public_key = load_public_key(recipient)
    if public_key is None:
        raise FileNotFoundError(f"Public key for '{recipient}' not found.")
    sym_key = Fernet.generate_key()
    f = Fernet(sym_key)
    enc_msg = f.encrypt(message.encode())
    enc_sym_key = public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(enc_sym_key).decode(), base64.b64encode(enc_msg).decode()

def decrypt_for_user(username, enc_sym_key_b64, enc_msg_b64):
    private_key = load_private_key(username)
    if private_key is None:
        raise FileNotFoundError(f"Private key for '{username}' not found.")
    try:
        enc_sym_key = base64.b64decode(enc_sym_key_b64)
        sym_key = private_key.decrypt(
            enc_sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        enc_msg = base64.b64decode(enc_msg_b64)
        f = Fernet(sym_key)
        plaintext = f.decrypt(enc_msg)
        return plaintext.decode()
    except Exception as e:
        raise e

def save_message(recipient, sender, enc_sym_key_b64, enc_msg_b64):
    with open(f"{recipient}_inbox.txt", "a") as f:
        f.write(f"From: {sender}\n")
        f.write(f"Key: {enc_sym_key_b64}\n")
        f.write(f"Message: {enc_msg_b64}\n")
        f.write("-" * 50 + "\n")

def read_inbox(username):
    path = f"{username}_inbox.txt"
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        content = f.read()
    blocks = [b.strip() for b in content.split("-" * 50) if b.strip()]
    msgs = []
    for block in blocks:
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        sender = ""
        key = ""
        msg = ""
        for line in lines:
            if line.lower().startswith("from:"):
                sender = line.split(":", 1)[1].strip()
            elif line.lower().startswith("key:"):
                key = line.split(":", 1)[1].strip()
            elif line.lower().startswith("message:"):
                msg = line.split(":", 1)[1].strip()
        if sender and key and msg:
            msgs.append({"from": sender, "key": key, "enc": msg})
    return msgs

class SecureChat:
    def __init__(self, root):
        self.root = root
        self.root.title("💻 Secure Chat - Hybrid RSA+AES (Fernet) Fullscreen")
        self.root.attributes("-fullscreen", True)
        self.root.configure(bg=BG)
        self.logged_in_user = None
        self.canvas = Canvas(root, bg=BG, highlightthickness=0)
        self.canvas.pack(fill=BOTH, expand=True)
        self.matrix_chars = string.ascii_letters + string.digits
        self.left = Frame(root, bg=PANEL_BG)
        self.left.place(relx=0.02, rely=0.03, relwidth=0.3, relheight=0.94)
        self.right = Frame(root, bg=PANEL_BG)
        self.right.place(relx=0.35, rely=0.03, relwidth=0.63, relheight=0.94)
        Label(self.left, text="🔐 LOGIN PANEL", bg=PANEL_BG, fg=ACCENT, font=FONT_HEADER).pack(pady=(10, 5))
        Label(self.left, text="Username", bg=PANEL_BG, fg=ACCENT, font=FONT_MAIN).pack(anchor=W, padx=15)
        self.username_var = StringVar()
        Entry(self.left, textvariable=self.username_var, font=FONT_MAIN, bg="#000", fg=ACCENT, insertbackground=ACCENT).pack(fill=X, padx=15, pady=5)
        Label(self.left, text="Password", bg=PANEL_BG, fg=ACCENT, font=FONT_MAIN).pack(anchor=W, padx=15)
        self.password_var = StringVar()
        Entry(self.left, textvariable=self.password_var, show="*", font=FONT_MAIN, bg="#000", fg=ACCENT, insertbackground=ACCENT).pack(fill=X, padx=15, pady=5)
        frame_btn = Frame(self.left, bg=PANEL_BG)
        frame_btn.pack(pady=10)
        Button(frame_btn, text="Login", command=self.login, width=10, bg=ACCENT, fg="black", font=FONT_MAIN).grid(row=0, column=0, padx=5)
        Button(frame_btn, text="Sign Up", command=self.signup, width=10, bg="#00ccff", fg="black", font=FONT_MAIN).grid(row=0, column=1, padx=5)
        Button(self.left, text="👥 Show All Users", command=self.show_all_users, width=25, bg="#00ffaa", fg="black", font=FONT_MAIN).pack(pady=10)
        Label(self.left, text="📥 INBOX", bg=PANEL_BG, fg=ACCENT, font=FONT_HEADER).pack(pady=(10, 5))
        self.inbox_list = Listbox(self.left, bg="#000", fg=ACCENT, selectbackground="#003300", font=("Consolas", 11))
        self.inbox_list.pack(fill=BOTH, expand=True, padx=15, pady=5)
        self.inbox_list.bind("<<ListboxSelect>>", self.show_message)
        Button(self.left, text="Refresh Inbox", command=self.load_inbox, bg=ACCENT_DIM, fg="black", font=FONT_MAIN).pack(pady=10)
        Label(self.right, text="💬 CHAT AREA", bg=PANEL_BG, fg=ACCENT, font=FONT_HEADER).pack(pady=10)
        Label(self.right, text="Recipient Username", bg=PANEL_BG, fg=ACCENT, font=FONT_MAIN).pack(anchor=W, padx=15)
        self.recipient_var = StringVar()
        Entry(self.right, textvariable=self.recipient_var, font=FONT_MAIN, bg="#000", fg=ACCENT, insertbackground=ACCENT).pack(fill=X, padx=15, pady=5)
        Label(self.right, text="Type your message below:", bg=PANEL_BG, fg=ACCENT, font=FONT_MAIN).pack(anchor=W, padx=15, pady=(10, 0))
        self.msg_box = scrolledtext.ScrolledText(self.right, height=10, font=("Consolas", 12), bg="#000", fg=ACCENT, insertbackground=ACCENT)
        self.msg_box.pack(fill=BOTH, padx=15, pady=5, expand=True)
        Button(self.right, text="Send Message", command=self.send_message, bg=ACCENT, fg="black", font=FONT_MAIN, width=20).pack(pady=10)
        Label(self.right, text="Decrypted Message Viewer", bg=PANEL_BG, fg=ACCENT, font=FONT_MAIN).pack(anchor=W, padx=15, pady=(10, 0))
        self.viewer = scrolledtext.ScrolledText(self.right, height=6, font=("Consolas", 12), bg="#000", fg=ACCENT, state=DISABLED)
        self.viewer.pack(fill=BOTH, padx=15, pady=(0, 10), expand=False)
        self.canvas.after(100, self.animate_matrix)
        root.bind("<Escape>", self.exit_fullscreen)

    def signup(self):
        u, p = self.username_var.get().strip(), self.password_var.get().strip()
        if not u or not p:
            messagebox.showwarning("Input", "Enter both username and password.")
            return
        if signup_user(u, p):
            messagebox.showinfo("Signup", f"User '{u}' registered successfully.")
            generate_rsa_keypair(u)
        else:
            messagebox.showerror("Error", "Username already exists!")

    def login(self):
        u, p = self.username_var.get().strip(), self.password_var.get().strip()
        if validate_login(u, p):
            self.logged_in_user = u
            messagebox.showinfo("Login", f"Welcome, {u}!")
            self.load_inbox()
        else:
            messagebox.showerror("Error", "Invalid credentials!")

    def load_inbox(self):
        self.inbox_list.delete(0, END)
        if not self.logged_in_user:
            return
        msgs = read_inbox(self.logged_in_user)
        self.inbox_data = msgs
        for i, msg in enumerate(msgs):
            self.inbox_list.insert(END, f"{i+1}. From: {msg['from']}")

    def show_message(self, event):
        sel = self.inbox_list.curselection()
        if not sel:
            return
        idx = sel[0]
        msg = self.inbox_data[idx]
        enc_key = msg["key"]
        enc = msg["enc"]
        try:
            dec = decrypt_for_user(self.logged_in_user, enc_key, enc)
        except Exception as e:
            dec = f"[Cannot decrypt message: {e}]"
        self.viewer.config(state=NORMAL)
        self.viewer.delete("1.0", END)
        self.viewer.insert(END, f"From: {msg['from']}\n\nEncrypted Key:\n{enc_key}\n\nEncrypted Message:\n{enc}\n\nDecrypted:\n{dec}")
        self.viewer.config(state=DISABLED)

    def send_message(self):
        if not self.logged_in_user:
            messagebox.showwarning("Login", "Login to send messages.")
            return
        rec, msg = self.recipient_var.get().strip(), self.msg_box.get("1.0", END).strip()
        if not rec or not msg:
            messagebox.showwarning("Input", "Recipient and message required.")
            return
        if not os.path.exists("users.txt"):
            messagebox.showerror("Error", "No users registered yet.")
            return
        if not any(line.startswith(rec + ":") for line in open("users.txt", "r")):
            messagebox.showerror("Error", "Recipient not found.")
            return
        try:
            enc_key_b64, enc_msg_b64 = encrypt_for_user(rec, msg)
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return
        save_message(rec, self.logged_in_user, enc_key_b64, enc_msg_b64)
        self.msg_box.delete("1.0", END)
        messagebox.showinfo("Sent", f"Message encrypted and sent to {rec}!")

    def show_all_users(self):
        users = get_all_users()
        if not users:
            messagebox.showinfo("Users", "No users registered yet.")
            return
        win = Toplevel(self.root)
        win.title("👥 All Registered Users")
        win.geometry("300x400")
        win.configure(bg=PANEL_BG)
        Label(win, text="Registered Users", bg=PANEL_BG, fg=ACCENT, font=FONT_HEADER).pack(pady=10)
        lb = Listbox(win, bg="#000", fg=ACCENT, font=("Consolas", 12))
        lb.pack(fill=BOTH, expand=True, padx=10, pady=10)
        for u in users:
            lb.insert(END, u)

    def animate_matrix(self):
        self.canvas.delete("matrix")
        w = self.root.winfo_screenwidth()
        h = self.root.winfo_screenheight()
        for _ in range(200):
            x = random.randint(0, w)
            y = random.randint(0, h)
            char = random.choice(self.matrix_chars)
            self.canvas.create_text(x, y, text=char, fill=ACCENT_DIM, font=("Consolas", 10, "bold"), tags="matrix")
        self.canvas.after(120, self.animate_matrix)

    def exit_fullscreen(self, event=None):
        self.root.attributes("-fullscreen", False)

if __name__ == "__main__":
    root = Tk()
    app = SecureChat(root)
    root.mainloop()
