import sqlite3
import tkinter as tk
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Thread
from tkinter import filedialog, messagebox, ttk

from cryptography.exceptions import UnsupportedAlgorithm
from PIL import Image, ImageTk

from .accounts import Accounts
from .images import image_preview
from .inbox import Inbox
from .protocol import MAX_IMAGE, Cipher, Message, send_message

CIPHER_NAMES = {"AES-256-GCM": Cipher.AES, "ChaCha20-Poly1305": Cipher.CHACHA}
CIPHER_LABELS = {cipher: label for label, cipher in CIPHER_NAMES.items()}


class Messenger:
    def __init__(self, root: tk.Tk, host: str, port: int, peer_port: int, database: Path):
        self.root = root
        self.accounts = Accounts(database)
        self.username: str | None = None
        self.image: bytes | None = None
        self.sending = False
        self.events = Queue(maxsize=32)
        self.messages: list[tuple[str, str, Image.Image, Cipher]] = []
        self.local_photo: ImageTk.PhotoImage | None = None
        self.received_photo: ImageTk.PhotoImage | None = None
        self.inbox = Inbox(host, port, self.receive, self.report_error)

        root.title(f"Обмен изображениями · {self.inbox.port}")
        root.geometry("1000x680")
        root.minsize(790, 590)
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        self.login = tk.StringVar()
        self.password = tk.StringVar()
        self.account_status = tk.StringVar(value="Гость · доступен приём")
        self.peer_host = tk.StringVar(value="127.0.0.1")
        self.peer_port = tk.StringVar(value=str(peer_port))
        self.cipher = tk.StringVar(value=next(iter(CIPHER_NAMES)))
        self.status = tk.StringVar(value=f"Приём на {host}:{self.inbox.port}")

        account = ttk.Frame(root, padding=(14, 12))
        account.grid(row=0, column=0, sticky="ew")
        ttk.Label(account, text="Логин").pack(side="left")
        ttk.Entry(account, textvariable=self.login, width=16).pack(side="left", padx=(5, 12))
        ttk.Label(account, text="Пароль").pack(side="left")
        password_entry = ttk.Entry(account, textvariable=self.password, width=16, show="•")
        password_entry.pack(side="left", padx=5)
        password_entry.bind("<Return>", lambda _event: self.sign_in())
        ttk.Button(account, text="Войти", command=self.sign_in).pack(side="left", padx=3)
        ttk.Button(account, text="Создать аккаунт", command=self.register).pack(side="left", padx=3)
        ttk.Button(account, text="Выйти", command=self.sign_out).pack(side="left", padx=3)
        ttk.Label(account, textvariable=self.account_status).pack(side="left", padx=10)

        panels = ttk.Panedwindow(root, orient="horizontal")
        panels.grid(row=1, column=0, sticky="nsew", padx=14)
        composer = ttk.LabelFrame(panels, text="Исходящее сообщение", padding=10)
        history = ttk.LabelFrame(panels, text="Входящие сообщения", padding=10)
        panels.add(composer, weight=1)
        panels.add(history, weight=1)
        self.build_composer(composer)
        self.build_history(history)
        ttk.Label(root, textvariable=self.status, padding=(14, 8)).grid(row=2, column=0, sticky="ew")
        root.after(50, self.process_events)

    def build_composer(self, panel: ttk.LabelFrame) -> None:
        network = ttk.Frame(panel)
        network.pack(fill="x")
        ttk.Label(network, text="Адрес").grid(row=0, column=0, sticky="w")
        ttk.Entry(network, textvariable=self.peer_host, width=19).grid(row=0, column=1, padx=5)
        ttk.Label(network, text="Порт").grid(row=0, column=2, sticky="w")
        ttk.Entry(network, textvariable=self.peer_port, width=7).grid(row=0, column=3, padx=5)
        ttk.Label(network, text="Шифр").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Combobox(
            network, textvariable=self.cipher, values=list(CIPHER_NAMES), state="readonly", width=20
        ).grid(row=1, column=1, columnspan=3, sticky="w", padx=5)

        ttk.Button(panel, text="Открыть PPM или JPEG…", command=self.open_image).pack(anchor="w", pady=5)
        self.local_preview = ttk.Label(panel, text="Изображение не выбрано", anchor="center")
        self.local_preview.pack(fill="both", expand=True)
        ttk.Label(panel, text="Текст сообщения").pack(anchor="w")
        self.outgoing_text = tk.Text(panel, height=5, width=32, wrap="word")
        self.outgoing_text.pack(fill="x", pady=(4, 8))
        self.send_button = ttk.Button(panel, text="Отправить", command=self.send, state="disabled")
        self.send_button.pack(anchor="e")

    def build_history(self, panel: ttk.LabelFrame) -> None:
        self.history = tk.Listbox(panel, height=4, width=32, exportselection=False)
        self.history.pack(fill="x")
        self.history.bind("<<ListboxSelect>>", lambda _event: self.show_received())
        self.received_preview = ttk.Label(panel, text="Ожидание сообщений", anchor="center")
        self.received_preview.pack(fill="both", expand=True)
        self.received_text = tk.Text(panel, height=5, width=32, state="disabled", wrap="word")
        self.received_text.pack(fill="x", pady=(4, 0))

    def register(self) -> None:
        username = self.login.get().strip()
        try:
            self.accounts.register(username, self.password.get())
        except (ValueError, sqlite3.Error) as error:
            messagebox.showerror("Создание аккаунта", str(error), parent=self.root)
            return
        self.set_user(username)
        self.status.set("Аккаунт создан.")

    def sign_in(self) -> None:
        username = self.login.get().strip()
        try:
            valid = self.accounts.authenticate(username, self.password.get())
        except sqlite3.Error as error:
            messagebox.showerror("Вход", str(error), parent=self.root)
            return
        if valid:
            self.set_user(username)
        else:
            self.password.set("")
            messagebox.showerror("Вход", "Неверный логин или пароль.", parent=self.root)

    def sign_out(self) -> None:
        self.set_user(None)

    def set_user(self, username: str | None) -> None:
        self.username = username
        self.password.set("")
        self.account_status.set(f"Вход: {username}" if username else "Гость · доступен приём")
        self.update_send_button()

    def update_send_button(self) -> None:
        enabled = self.username is not None and self.image is not None and not self.sending
        self.send_button.configure(state="normal" if enabled else "disabled")

    def open_image(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root, filetypes=[("PPM и JPEG", ("*.ppm", "*.jpg", "*.jpeg")), ("Все файлы", "*")]
        )
        if not path:
            return
        try:
            with Path(path).open("rb") as source:
                data = source.read(MAX_IMAGE + 1)
            if len(data) > MAX_IMAGE:
                raise ValueError("Выберите изображение размером до 16 МиБ.")
            self.local_photo = ImageTk.PhotoImage(image_preview(data))
        except (OSError, ValueError) as error:
            messagebox.showerror("Открытие изображения", str(error), parent=self.root)
            return
        self.image = data
        self.local_preview.configure(image=self.local_photo, text="")
        self.status.set(f"Открыто изображение {Path(path).name}")
        self.update_send_button()

    def send(self) -> None:
        if self.username is None or self.image is None or self.sending:
            return
        host = self.peer_host.get().strip()
        try:
            port = int(self.peer_port.get())
            if not host or not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Отправка", "Введите адрес и порт от 1 до 65535.", parent=self.root)
            return
        message = Message(self.username, self.outgoing_text.get("1.0", "end-1c"), self.image)
        cipher = CIPHER_NAMES[self.cipher.get()]
        self.sending = True
        self.update_send_button()
        self.status.set(f"Отправка на {host}:{port}…")
        Thread(target=self.send_in_background, args=(host, port, message, cipher), daemon=True).start()

    def send_in_background(self, host: str, port: int, message: Message, cipher: Cipher) -> None:
        try:
            send_message(host, port, message, cipher)
        except (OSError, ValueError, UnsupportedAlgorithm) as error:
            status = f"Ошибка отправки: {error}"
        else:
            status = "Получатель подтвердил приём сообщения."
        self.events.put(("sent", status))

    def receive(self, message: Message, cipher: Cipher) -> None:
        preview = image_preview(message.image)
        try:
            self.events.put_nowait(("received", (message.username, message.text, preview, cipher)))
        except Full as error:
            raise ValueError("Очередь входящих сообщений заполнена.") from error

    def report_error(self, error: str) -> None:
        try:
            self.events.put_nowait(("error", error))
        except Full:
            pass

    def process_events(self) -> None:
        for _ in range(16):
            try:
                event, data = self.events.get_nowait()
            except Empty:
                break
            if event == "received":
                self.messages.insert(0, data)
                self.history.insert(0, f"{data[0]} · {CIPHER_LABELS[data[3]]}")
                if len(self.messages) > 20:
                    self.messages.pop()
                    self.history.delete(20)
                self.history.selection_clear(0, "end")
                self.history.selection_set(0)
                self.history.see(0)
                self.show_received()
                self.status.set("Входящее сообщение прошло проверку CRC-32.")
            elif event == "sent":
                self.sending = False
                self.update_send_button()
                self.status.set(data)
            else:
                self.status.set(data)
        self.root.after(50, self.process_events)

    def show_received(self) -> None:
        selected = self.history.curselection()
        if not selected:
            return
        _, text, preview, _ = self.messages[selected[0]]
        self.received_photo = ImageTk.PhotoImage(preview)
        self.received_preview.configure(image=self.received_photo, text="")
        self.received_text.configure(state="normal")
        self.received_text.delete("1.0", "end")
        self.received_text.insert("1.0", text)
        self.received_text.configure(state="disabled")

    def close(self) -> None:
        self.inbox.close()
        self.root.destroy()
