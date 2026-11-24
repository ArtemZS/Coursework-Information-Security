import argparse
import sqlite3
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

from .ui import Messenger


def port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Порт должен быть числом.") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("Порт должен быть от 1 до 65535.")
    return port


def main() -> int:
    parser = argparse.ArgumentParser(description="Графическое приложение для обмена изображениями и текстом.")
    parser.add_argument("--listen-host", default="127.0.0.1", help="IPv4-адрес для приёма")
    parser.add_argument("--listen-port", type=port_number, default=9001, help="Порт для приёма")
    parser.add_argument("--peer-port", type=port_number, default=9002, help="Порт получателя по умолчанию")
    parser.add_argument("--db", type=Path, default=Path(".data/accounts.sqlite3"), help="Файл базы учётных записей")
    options = parser.parse_args()

    root = tk.Tk()
    try:
        Messenger(root, options.listen_host, options.listen_port, options.peer_port, options.db)
    except (OSError, sqlite3.Error) as error:
        root.withdraw()
        messagebox.showerror("Ошибка запуска", str(error), parent=root)
        root.destroy()
        return 1
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
