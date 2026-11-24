import socket
from collections.abc import Callable
from threading import Event, Thread

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa

from .protocol import RSA_BITS, TIMEOUT, Cipher, Message, receive_message


class Inbox:
    def __init__(
        self,
        host: str,
        port: int,
        deliver: Callable[[Message, Cipher], None],
        report_error: Callable[[str], None],
    ):
        self.stopped = Event()
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
        self.listener = socket.socket()
        try:
            self.listener.bind((host, port))
            self.listener.listen(5)
            self.listener.settimeout(0.25)
            self.port = self.listener.getsockname()[1]
        except OSError:
            self.listener.close()
            raise
        Thread(target=self.listen, args=(deliver, report_error), daemon=True).start()

    def listen(self, deliver: Callable[[Message, Cipher], None], report_error: Callable[[str], None]) -> None:
        with self.listener:
            while not self.stopped.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError as error:
                    if not self.stopped.is_set():
                        report_error(f"Ошибка приёма: {error}")
                    return
                with connection:
                    connection.settimeout(TIMEOUT)
                    try:
                        deliver(*receive_message(connection, self.private_key))
                    except (OSError, ValueError, UnsupportedAlgorithm) as error:
                        report_error(f"Входящее сообщение отклонено: {error}")
                        self.acknowledge(connection, b"\x00")
                    else:
                        self.acknowledge(connection, b"\x01")

    @staticmethod
    def acknowledge(connection: socket.socket, result: bytes) -> None:
        try:
            connection.sendall(result)
        except OSError:
            pass

    def close(self) -> None:
        self.stopped.set()
        self.listener.close()
