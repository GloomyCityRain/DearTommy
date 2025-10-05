import tkinter as tk
from datetime import datetime
from tkinter import messagebox
from cryptography.fernet import Fernet
import os, base64, hashlib


# -----------------------------
# EMBEDDED CREDENTIAL STORE
# -----------------------------
# # Paste your generated JSON here. IN HERE, I KNOW I WILL MISS THIS IF I DON'T MAKE IT REALLY OBVIOUS
CREDENTIAL_STORE = {
 
}


# -----------------------------
# Helper functions for encryption
# -----------------------------
def verify_user(username: str, password: str) -> bool:
    #Verify username/password using PBKDF2 stored hash in CREDENTIAL_STORE.
    info = CREDENTIAL_STORE.get(username)
    if not info:
        return False
    salt = base64.b64decode(info["salt"])
    expected = base64.b64decode(info["dk"])
    iterations = info["iterations"]
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return dk == expected

def generate_key_from_password(password: str) -> bytes:
    #Generate a Fernet key from a user password
    hash_bytes = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hash_bytes)

def encrypt_text(text: str, key: bytes) -> bytes:
    cipher = Fernet(key)
    return cipher.encrypt(text.encode())

def decrypt_text(token: bytes, key: bytes) -> str:
    cipher = Fernet(key)
    return cipher.decrypt(token).decode()

# -----------------------------
# Files. This will also create the folder and encrypt the plaintext
# -----------------------------
FOLDER = "./saved_files"
os.makedirs(FOLDER, exist_ok=True)

# -----------------------------
# Styles. Feel free to mess with this, personally I'm not completely sold on the style but I'm sick of looking at it 
# -----------------------------
BG_COLOR = "#f0f4f8"
FRAME_COLOR = "#ffffff"
BUTTON_COLOR = "#4a90e2"
BUTTON_HOVER_COLOR = "#357ABD"
BUTTON_TEXT_COLOR = "#ffffff"
TEXT_BG = "#fefefe"

BUTTON_FONT = ("Lexend", 12, "bold")
TITLE_FONT = ("Lexend", 16, "bold")
TEXT_FONT = ("Lexend", 11)

def style_button(btn):
    btn.config(bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, activebackground=BUTTON_HOVER_COLOR, relief="flat", bd=0)
    btn.bind("<Enter>", lambda e: btn.config(bg=BUTTON_HOVER_COLOR))
    btn.bind("<Leave>", lambda e: btn.config(bg=BUTTON_COLOR))

# -----------------------------
# Main App
# -----------------------------
class DearTommy(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Dear Tommy")
        self.geometry("800x600")
        self.configure(bg=BG_COLOR)

        self.current_user = None
        self.current_key = None

        container = tk.Frame(self, bg=BG_COLOR)
        container.grid(row=0, column=0, sticky="nsew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (LoginPage, ContentsPage, DiaryPage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # Make sure login page is shown first
        self.show_frame(LoginPage)


    def show_frame(self, frame_class):
        frame = self.frames[frame_class]
        frame.tkraise()
        
        #Load contents once user is logged in 
        if hasattr(frame, "load_contents"):
            frame.load_contents()

    def login(self, username_input, password_input):
        username = username_input.get()
        password = password_input.get()
        # Use verify_user() — compares PBKDF2 hashes stored in the embedded dict
        if verify_user(username, password):
            self.current_user = username
            self.current_key = generate_key_from_password(password)
            self.show_frame(ContentsPage)
        else:
            messagebox.showerror("Login Failed", "Incorrect username or password.")

# -----------------------------
# Login Page. This is mostly just buttons
# -----------------------------
class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=BG_COLOR)
        self.controller = controller

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        frame = tk.Frame(self, bg=FRAME_COLOR, padx=30, pady=30)
        frame.grid(row=1, column=0, pady=50, padx=50)

        tk.Label(frame, text="Dear Tommy", font=TITLE_FONT, bg=FRAME_COLOR).grid(row=0, column=0, columnspan=3, pady=(0, 20))

        tk.Label(frame, text="Username:", font=BUTTON_FONT, bg=FRAME_COLOR).grid(row=1, column=0, sticky="e", padx=5, pady=5)
        username_input = tk.Entry(frame, font=BUTTON_FONT, width=20)
        username_input.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(frame, text="Password:", font=BUTTON_FONT, bg=FRAME_COLOR).grid(row=2, column=0, sticky="e", padx=5, pady=5)
        password_input = tk.Entry(frame, font=BUTTON_FONT, show="*", width=20)
        password_input.grid(row=2, column=1, padx=5, pady=5)

        show_var = tk.IntVar()
        tk.Checkbutton(frame, text="Show Password", font=BUTTON_FONT, variable=show_var, command=lambda: password_input.config(show="" if show_var.get() else "*"), bg=FRAME_COLOR).grid(row=2, column=2, padx=5, pady=5)

        login_btn = tk.Button(frame, text="Login", font=BUTTON_FONT, command=lambda: controller.login(username_input, password_input))
        login_btn.grid(row=3, column=0, columnspan=3, pady=20, ipadx=10, ipady=5)
        style_button(login_btn)

        tk.Label(self, text="Deers", font=("Lexend", 10), bg=BG_COLOR).grid(row=3, column=0, pady=10)

# -----------------------------
# Contents Page
# -----------------------------
class ContentsPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=BG_COLOR)
        self.controller = controller
        self.current_file = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        frame = tk.Frame(self, bg=FRAME_COLOR, padx=20, pady=20)
        frame.grid(row=1, column=0, pady=20, padx=20)

        tk.Label(frame, text="Diary Contents", font=TITLE_FONT, bg=FRAME_COLOR).pack(pady=10)

        content_frame = tk.Frame(frame, bg=FRAME_COLOR)
        content_frame.pack()

        self.listbox = tk.Listbox(content_frame, width=30)
        self.listbox.pack(side="left", fill="y", padx=(0, 10))
        self.listbox.bind("<<ListboxSelect>>", self.load_selected_file)

        self.text_area = tk.Text(content_frame, width=60, height=20, font=TEXT_FONT, bg=TEXT_BG, wrap="word")
        self.text_area.pack(side="left", fill="both", expand=True)
        self.text_area.config(state="disabled")

        button_frame = tk.Frame(frame, bg=FRAME_COLOR)
        button_frame.pack(pady=10)

        btn_options = [
            ("New Entry", self.new_entry),
            ("Edit Entry", self.edit_selected_entry),
            ("Refresh", self.load_contents),
            ("Logout", self.logout)
        ]

        for i, (text, cmd) in enumerate(btn_options):
            btn = tk.Button(button_frame, text=text, font=BUTTON_FONT, command=cmd)
            btn.grid(row=0, column=i, padx=5, ipadx=10, ipady=5)
            style_button(btn)

        tk.Label(self, text="Deers", font=("Lexend", 10), bg=BG_COLOR).grid(row=3, column=0, pady=10)


    def load_contents(self):
        self.listbox.delete(0, tk.END)
        self.text_area.config(state="normal")
        self.text_area.delete("1.0", tk.END)

        #Checks the current user
        current_user = self.controller.current_user
        if current_user == None:
            self.text_area.insert(tk.END, "No user logged in.")
            self.text_area.config(state="disabled")
            return
        
        #Only loads up entries from the current user
        txt_files = sorted([f for f in os.listdir(FOLDER) 
                            if f.endswith(".txt") and f.startswith(current_user)])


        for f in txt_files:
            self.listbox.insert(tk.END, f)
        self.text_area.insert(tk.END, "Select a file to view its contents.")
        self.text_area.config(state="disabled")

    def load_selected_file(self, event):
        selection = self.listbox.curselection()
        if not selection:
            return
        filename = self.listbox.get(selection[0])
        filepath = os.path.join(FOLDER, filename)
        try:
            with open(filepath, "rb") as f:
                encrypted = f.read().strip()
                decrypted = decrypt_text(encrypted, self.controller.current_key)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file:\n{e}")
            return
        self.text_area.config(state="normal")
        self.text_area.delete("1.0", tk.END)
        self.text_area.insert(tk.END, decrypted)
        self.text_area.config(state="disabled")

    def edit_selected_entry(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showinfo("Select a file to edit")
            return
        filename = self.listbox.get(selection[0])
        filepath = os.path.join(FOLDER, filename)
        try:
            with open(filepath, "rb") as f:
                encrypted = f.read().strip()
            decrypted = decrypt_text(encrypted, self.controller.current_key)
        except Exception as e:
            messagebox.showerror("Error", f"Could not decrypt file:\n{e}")
            return
        diary_page = self.controller.frames[DiaryPage]
        diary_page.load_existing_entry(filename, decrypted)
        self.controller.show_frame(DiaryPage)

    def new_entry(self):
        self.controller.show_frame(DiaryPage)

    def logout(self):
        self.controller.current_user = None
        self.controller.current_key = None
        self.controller.show_frame(LoginPage)

# -----------------------------
# Diary Page
# -----------------------------
class DiaryPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=BG_COLOR)
        self.controller = controller
        self.current_file = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        frame = tk.Frame(self, bg=FRAME_COLOR, padx=20, pady=20)
        frame.grid(row=1, column=0, pady=20, padx=20)

        self.date_label = tk.Label(frame, text=datetime.now().strftime("%d/%m/%y"), font=TITLE_FONT, bg=FRAME_COLOR)
        self.date_label.pack(pady=10)

        self.text_area = tk.Text(frame, width=70, height=20, font=TEXT_FONT, bg=TEXT_BG, wrap="word")
        self.text_area.pack(pady=10)

        button_frame = tk.Frame(frame, bg=FRAME_COLOR)
        button_frame.pack(pady=10)

        btn_options = [
            ("Save Entry", self.save_entry),
            ("Contents Page", self.contents_page),
            ("Logout", self.logout)
        ]

        #Enumerable for buttons. thank god for unity 
        for i, (text, cmd) in enumerate(btn_options):
            btn = tk.Button(button_frame, text=text, font=BUTTON_FONT, command=cmd)
            btn.grid(row=0, column=i, padx=5, ipadx=10, ipady=5)
            style_button(btn)

        tk.Label(self, text="Deers", font=("Lexend", 10), bg=BG_COLOR).grid(row=3, column=0, pady=10)

    def load_existing_entry(self, filename, content):
        self.current_file = filename
        self.text_area.delete("1.0", tk.END)
        self.text_area.insert(tk.END, content)
        self.date_label.config(text=f"Editing: {filename}" if filename else datetime.now().strftime("%d/%m/%y"))

    def save_entry(self):
        entry = self.text_area.get("1.0", tk.END).strip()
        if not entry:
            messagebox.showinfo("Not saving", "There is no text to save.")
            return
        encrypted = encrypt_text(entry, self.controller.current_key)
        if self.current_file:
            filepath = os.path.join(FOLDER, self.current_file)
        else:
            date_str = datetime.now().strftime("%d_%m_%y_%H-%M-%S")
            self.current_file = f"{self.controller.current_user} {date_str}.txt"
            filepath = os.path.join(FOLDER, self.current_file)
        with open(filepath, "wb") as f:
            f.write(encrypted)
        self.text_area.delete("1.0", tk.END)
        messagebox.showinfo("Saved", "Diary entry saved!")
        self.current_file = None

    def contents_page(self):
        self.controller.show_frame(ContentsPage)
        self.controller.frames[ContentsPage].load_contents()

    def logout(self):
        self.text_area.delete("1.0", tk.END)
        self.controller.current_user = None
        self.controller.current_key = None
        self.current_file = None
        self.controller.show_frame(LoginPage)

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    app = DearTommy()
    app.mainloop()

