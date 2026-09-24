"""Check the embedding safety guard without a cross toolchain."""
import importlib.util
from pathlib import Path
import struct
import unittest

root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("embed", root / "scripts/embed_boot_key_relay.py")
embed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(embed)


class EmbedTest(unittest.TestCase):
    def fixture(self):
        image = bytearray(256)
        image[:2] = b"MZ"
        struct.pack_into("<I", image, 0x3C, 64)
        image[64:68] = b"PE\0\0"
        struct.pack_into("<H", image, 68, 0xAA64)
        struct.pack_into("<H", image, 88, 0x20B)
        struct.pack_into("<H", image, 156, 11)
        return image

    def test_driver(self):
        self.assertIn("mBootKeyRelayImage[]", embed.render(self.fixture()))

    def test_application_is_rejected(self):
        image = self.fixture()
        struct.pack_into("<H", image, 156, 10)
        with self.assertRaises(ValueError):
            embed.render(image)

    def test_malformed_and_oversized(self):
        for image in (b"", bytes(256), self.fixture() + bytes(32768)):
            with self.assertRaises(ValueError):
                embed.render(image)
        image = self.fixture()
        struct.pack_into("<I", image, 0x3C, 0xFFFFFFFF)
        with self.assertRaises(ValueError):
            embed.render(image)


if __name__ == "__main__":
    unittest.main()
