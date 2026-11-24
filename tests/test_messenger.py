import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from queue import Queue

from image_messenger.accounts import Accounts
from image_messenger.images import image_preview
from image_messenger.inbox import Inbox
from image_messenger.protocol import Cipher, Message, decode_message, encode_message, send_message

PPM = b"P6\n2 1\n255\n\x00\xff\x00\x00\x00\xff"


class AccountsTest(unittest.TestCase):
    def test_account_persists_with_salted_password_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "accounts.sqlite3"
            accounts = Accounts(database)
            accounts.register("Алиса", "correct-password")
            accounts.register("Боб", "correct-password")
            with self.assertRaises(ValueError):
                accounts.register("Алиса", "another-password")

            reopened = Accounts(database)
            self.assertTrue(reopened.authenticate("Алиса", "correct-password"))
            self.assertFalse(reopened.authenticate("Алиса", "incorrect-password"))
            self.assertFalse(reopened.authenticate("Гость", "correct-password"))
            with closing(sqlite3.connect(database)) as connection:
                hashes = connection.execute("SELECT salt, password_hash FROM accounts").fetchall()
            self.assertNotEqual(hashes[0][0], hashes[1][0])
            self.assertNotEqual(hashes[0][1], hashes[1][1])


class MessagingTest(unittest.TestCase):
    def test_crc_rejects_corrupted_payload(self):
        packet = bytearray(encode_message(Message("Алиса", "Привет", PPM)))
        packet[-5] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC-32"):
            decode_message(bytes(packet))

    def test_guest_inbox_receives_both_ciphers(self):
        deliveries = Queue()
        errors = Queue()

        def deliver(message, cipher):
            preview = image_preview(message.image)
            deliveries.put((message, cipher, preview.getpixel((0, 0))))

        inbox = Inbox("127.0.0.1", 0, deliver, errors.put)
        self.addCleanup(inbox.close)
        message = Message("Алиса", "Привет, Боб!", PPM)
        for cipher in Cipher:
            with self.subTest(cipher=cipher):
                send_message("127.0.0.1", inbox.port, message, cipher)
                self.assertEqual(deliveries.get(timeout=1), (message, cipher, (0, 255, 0)))
        self.assertTrue(errors.empty())

    def test_invalid_image_is_rejected_and_inbox_stays_available(self):
        errors = Queue()

        def deliver(message, _cipher):
            image_preview(message.image)

        inbox = Inbox("127.0.0.1", 0, deliver, errors.put)
        self.addCleanup(inbox.close)
        with self.assertRaisesRegex(ValueError, "отклонил"):
            send_message("127.0.0.1", inbox.port, Message("Алиса", "", b"invalid"), Cipher.AES)
        self.assertIn("PPM или JPEG", errors.get(timeout=1))
        send_message("127.0.0.1", inbox.port, Message("Алиса", "", PPM), Cipher.AES)
