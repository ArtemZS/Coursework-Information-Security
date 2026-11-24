import secrets
import socket
import struct
import zlib
from dataclasses import dataclass
from enum import IntEnum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

MAGIC = b"IM01"
SIZE = struct.Struct("!I")
MESSAGE_HEADER = struct.Struct("!III")
MAX_USERNAME = 128
MAX_TEXT = 256 * 1024
MAX_IMAGE = 16 * 1024 * 1024
MAX_PACKET = MAX_USERNAME + MAX_TEXT + MAX_IMAGE + 1024
TIMEOUT = 10
RSA_BITS = 2048
RSA_BYTES = RSA_BITS // 8
NONCE_BYTES = 12
OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
)


class Cipher(IntEnum):
    AES = 1
    CHACHA = 2


CIPHERS = {Cipher.AES: AESGCM, Cipher.CHACHA: ChaCha20Poly1305}


@dataclass(frozen=True)
class Message:
    username: str
    text: str
    image: bytes


def encode_message(message: Message) -> bytes:
    username, text = message.username.encode(), message.text.encode()
    if not (0 < len(username) <= MAX_USERNAME and len(text) <= MAX_TEXT):
        raise ValueError("Проверьте имя отправителя и размер текста (до 256 КиБ в UTF-8).")
    if not 0 < len(message.image) <= MAX_IMAGE:
        raise ValueError("Выберите изображение размером до 16 МиБ.")
    body = MESSAGE_HEADER.pack(len(username), len(text), len(message.image))
    body += username + text + message.image
    return body + SIZE.pack(zlib.crc32(body))


def decode_message(payload: bytes) -> Message:
    if len(payload) < MESSAGE_HEADER.size + SIZE.size:
        raise ValueError("Сообщение неполное.")
    body, checksum = payload[:-SIZE.size], payload[-SIZE.size:]
    if zlib.crc32(body) != SIZE.unpack(checksum)[0]:
        raise ValueError("Контрольная сумма CRC-32 не совпадает.")
    username_size, text_size, image_size = MESSAGE_HEADER.unpack_from(body)
    username_end = MESSAGE_HEADER.size + username_size
    text_end = username_end + text_size
    if not (
        0 < username_size <= MAX_USERNAME
        and text_size <= MAX_TEXT
        and 0 < image_size <= MAX_IMAGE
        and len(body) == text_end + image_size
    ):
        raise ValueError("Недопустимый размер полей сообщения.")
    return Message(
        body[MESSAGE_HEADER.size:username_end].decode(),
        body[username_end:text_end].decode(),
        body[text_end:],
    )


def read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray(size)
    remaining = memoryview(data)
    while remaining:
        count = connection.recv_into(remaining)
        if count == 0:
            raise ConnectionError("Соединение закрыто до завершения передачи.")
        remaining = remaining[count:]
    return bytes(data)


def read_frame(connection: socket.socket, limit: int) -> bytes:
    (size,) = SIZE.unpack(read_exact(connection, SIZE.size))
    if not 0 < size <= limit:
        raise ValueError("Недопустимый размер сетевого пакета.")
    return read_exact(connection, size)


def write_frame(connection: socket.socket, data: bytes) -> None:
    connection.sendall(SIZE.pack(len(data)))
    connection.sendall(data)


def send_message(host: str, port: int, message: Message, cipher: Cipher) -> None:
    payload = encode_message(message)
    with socket.create_connection((host, port), timeout=TIMEOUT) as connection:
        if read_exact(connection, len(MAGIC)) != MAGIC:
            raise ValueError("Несовместимая версия протокола.")
        peer_key = serialization.load_der_public_key(read_frame(connection, 1024))
        if not isinstance(peer_key, rsa.RSAPublicKey) or peer_key.key_size != RSA_BITS:
            raise ValueError("Получен недопустимый ключ RSA.")
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(NONCE_BYTES)
        header = MAGIC + bytes([cipher]) + nonce + peer_key.encrypt(key, OAEP)
        ciphertext = CIPHERS[cipher](key).encrypt(nonce, payload, header)
        write_frame(connection, header + ciphertext)
        if read_exact(connection, 1) != b"\x01":
            raise ValueError("Получатель отклонил сообщение.")


def receive_message(connection: socket.socket, private_key: rsa.RSAPrivateKey) -> tuple[Message, Cipher]:
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    connection.sendall(MAGIC)
    write_frame(connection, public_key)
    packet = read_frame(connection, MAX_PACKET)
    nonce_start = len(MAGIC) + 1
    key_start = nonce_start + NONCE_BYTES
    header_end = key_start + RSA_BYTES
    if len(packet) < header_end + 16 or not packet.startswith(MAGIC):
        raise ValueError("Недопустимый заголовок сообщения.")
    try:
        cipher = Cipher(packet[len(MAGIC)])
        key = private_key.decrypt(packet[key_start:header_end], OAEP)
        if len(key) != 32:
            raise ValueError("Недопустимая длина ключа.")
        payload = CIPHERS[cipher](key).decrypt(
            packet[nonce_start:key_start], packet[header_end:], packet[:header_end]
        )
    except (ValueError, InvalidTag) as error:
        raise ValueError("Не удалось расшифровать или проверить сообщение.") from error
    return decode_message(payload), cipher
