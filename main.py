import tkinter as tk
from tkinter import messagebox, scrolledtext
import random
import string
import requests
from cryptography.fernet import Fernet
import os
import json
import hashlib

# ------------------------
# Encryption / Save Setup
# ------------------------
KEY_FILE = "secret.key"
DATA_FILE = "passwords.dat"

def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)

def load_key():
    with open(KEY_FILE, "rb") as f:
        return f.read()

def save_password(site, username, password):
    key = load_key()
    fernet = Fernet(key)
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "rb") as f:
            encrypted_data = f.read()
            data = json.loads(fernet.decrypt(encrypted_data)) if encrypted_data else {}
    else:
        data = {}
    data[site] = {"username": username, "password": password}
    encrypted_data = fernet.encrypt(json.dumps(data).encode())
    with open(DATA_FILE, "wb") as f:
        f.write(encrypted_data)

def load_passwords():
    key = load_key()
    fernet = Fernet(key)
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "rb") as f:
            encrypted_data = f.read()
            return json.loads(fernet.decrypt(encrypted_data)) if encrypted_data else {}
    return {}

# ------------------------
# Password Generator
# ------------------------
def generate_password(length=12, complexity="all"):
    chars = ""
    if complexity == "letters":
        chars = string.ascii_letters
    elif complexity == "letters_digits":
        chars = string.ascii_letters + string.digits
    else:
        chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(chars) for _ in range(length))

# ------------------------
# Leak Checker
# ------------------------
def check_password_leak(password):
    sha1pwd = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1pwd[:5]
    suffix = sha1pwd[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return "Error"
        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except:
        return "Error"

# ------------------------
# GUI Setup
# ------------------------
generate_key()
root = tk.Tk()
root.title("SecurePass - Password Manager")
root.geometry("520x520")
root.config(bg="#0d0d0d")

main_frame = tk.Frame(root, bg="#1a1a1a")
main_frame.pack(pady=20, padx=20, fill="both", expand=True)

# --- Input Fields ---
tk.Label(main_frame, text="Site / App:", bg="#1a1a1a", fg="white").pack(pady=5, anchor="w")
site_entry = tk.Entry(main_frame, font=("Montserrat", 12), width=40)
site_entry.pack(pady=5)

tk.Label(main_frame, text="Username / Email:", bg="#1a1a1a", fg="white").pack(pady=5, anchor="w")
username_entry = tk.Entry(main_frame, font=("Montserrat", 12), width=40)
username_entry.pack(pady=5)

tk.Label(main_frame, text="Generated Password:", bg="#1a1a1a", fg="white").pack(pady=5, anchor="w")
password_entry = tk.Entry(main_frame, font=("Montserrat", 12), width=40)
password_entry.pack(pady=5)

leak_label = tk.Label(main_frame, text="", bg="#1a1a1a", fg="white")
leak_label.pack(pady=5)

# --- Password Settings ---
settings_frame = tk.Frame(main_frame, bg="#1a1a1a")
settings_frame.pack(pady=5)

tk.Label(settings_frame, text="Length:", bg="#1a1a1a", fg="white").grid(row=0, column=0, sticky="w")
length_var = tk.IntVar(value=12)
tk.Spinbox(settings_frame, from_=8, to=24, textvariable=length_var, width=5).grid(row=0, column=1, padx=5)

tk.Label(settings_frame, text="Complexity:", bg="#1a1a1a", fg="white").grid(row=0, column=2, padx=10, sticky="w")
complexity_var = tk.StringVar(value="all")
tk.OptionMenu(settings_frame, complexity_var, "letters", "letters_digits", "all").grid(row=0, column=3, sticky="w")

# ------------------------
# Functions
# ------------------------
def generate_pwd():
    pwd = generate_password(length_var.get(), complexity_var.get())
    password_entry.delete(0, tk.END)
    password_entry.insert(0, pwd)
    leak_label.config(text="")

def leak_and_save():
    site = site_entry.get().strip()
    username = username_entry.get().strip()
    pwd = password_entry.get()
    if not site or not username or not pwd:
        messagebox.showwarning("Missing Info", "Fill site, username, and generate a password first!")
        return
    count = check_password_leak(pwd)
    if count == "Error":
        messagebox.showerror("Error", "Could not check password leak.")
        return
    if count > 0:
        leak_label.config(text=f"Leak Check: Found {count} times! ❌")
        messagebox.showwarning("Leaked Password", f"This password has been found {count} times!\nNot saved.")
    else:
        leak_label.config(text="Leak Check: Safe ✅")
        save_password(site, username, pwd)
        messagebox.showinfo("Saved", f"Password for {site} saved successfully!")

def view_saved():
    saved_pw = load_passwords()
    if not saved_pw:
        messagebox.showinfo("No Passwords", "No saved passwords found.")
        return

    view_win = tk.Toplevel(root)
    view_win.title("Saved Passwords")
    view_win.geometry("500x400")
    view_win.config(bg="#1a1a1a")

    tk.Label(view_win, text="Search by Site/App:", bg="#1a1a1a", fg="white").pack(pady=5)
    search_var = tk.StringVar()
    search_entry = tk.Entry(view_win, textvariable=search_var, font=("Montserrat", 12))
    search_entry.pack(pady=5, fill="x", padx=10)

    scroll = scrolledtext.ScrolledText(view_win, bg="#222", fg="white", font=("Montserrat", 12))
    scroll.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh_display(*args):
        scroll.config(state="normal")
        scroll.delete(1.0, tk.END)
        query = search_var.get().lower()
        for site, info in saved_pw.items():
            if query in site.lower():
                scroll.insert(tk.END, f"Site: {site}\nUsername: {info['username']}\nPassword: {info['password']}\n{'-'*30}\n")
        scroll.config(state="disabled")

    search_var.trace_add("write", refresh_display)
    refresh_display()  # initial populate

# ------------------------
# Buttons
# ------------------------
buttons_frame = tk.Frame(main_frame, bg="#1a1a1a")
buttons_frame.pack(pady=15)

tk.Button(buttons_frame, text="Generate Password", bg="#00aced", fg="white", width=25, command=generate_pwd).grid(row=0, column=0, padx=5, pady=5)
tk.Button(buttons_frame, text="Check Leak & Save", bg="#00cc66", fg="white", width=25, command=leak_and_save).grid(row=0, column=1, padx=5, pady=5)
tk.Button(buttons_frame, text="View Saved Passwords", bg="#ffaa00", fg="white", width=25, command=view_saved).grid(row=1, column=0, columnspan=2, pady=5)
tk.Button(buttons_frame, text="Exit", bg="#ff4d4d", fg="white", width=25, command=root.destroy).grid(row=2, column=0, columnspan=2, pady=10)

root.mainloop()
