from PIL import Image
import random
import hashlib


# -----------------------------
# Helpers: Convert bytes <-> bits
# -----------------------------
def to_bits(data: bytes):
    return [(byte >> i) & 1 for byte in data for i in range(8)]


def from_bits(bits):
    out = bytearray()
    for b in range(0, len(bits), 8):
        byte = 0
        for i in range(8):
            byte |= bits[b + i] << i
        out.append(byte)
    return bytes(out)


# -----------------------------
# EMBED DATA INTO IMAGE (LSB)
# -----------------------------
def embed_data_lsb(host_img_path, stego_img_path, data: bytes, stego_key: str):
    # Convert any image to safe RGB
    img = Image.open(host_img_path).convert("RGB")
    pixels = img.load()
    w, h = img.size

    total_slots = w * h * 3  # R,G,B slots

    bits = to_bits(data)

    # Add 32-bit header for length
    header = len(bits).to_bytes(4, "big")
    header_bits = to_bits(header)
    payload = header_bits + bits

    if len(payload) > total_slots:
        raise ValueError("Image too small to hide data!")

    # Randomize positions using stego key
    seed = int(hashlib.sha256(stego_key.encode()).hexdigest(), 16)
    random.seed(seed)

    positions = list(range(total_slots))
    random.shuffle(positions)

    # Insert bits
    for i, bit in enumerate(payload):
        pos = positions[i]
        pixel_idx = pos // 3
        ch = pos % 3

        x = pixel_idx % w
        y = pixel_idx // w

        r, g, b = pixels[x, y]
        channels = [r, g, b]

        # Write bit into LSB
        channels[ch] = (channels[ch] & 0xFE) | bit

        pixels[x, y] = tuple(channels)

    # Ensure PNG format for output
    if not stego_img_path.lower().endswith((".png", ".jpg", ".jpeg", ".bmp")):
        stego_img_path = stego_img_path + ".png"

    # Explicitly specify format to avoid "unknown file extension" error
    img.save(stego_img_path, format="PNG")


# -----------------------------
# EXTRACT DATA FROM IMAGE (LSB)
# -----------------------------
def extract_data_lsb(stego_img_path, stego_key: str):
    img = Image.open(stego_img_path).convert("RGB")
    pixels = img.load()
    w, h = img.size

    total_slots = w * h * 3

    # Same random positions (must match embed)
    seed = int(hashlib.sha256(stego_key.encode()).hexdigest(), 16)
    random.seed(seed)

    positions = list(range(total_slots))
    random.shuffle(positions)

    # Extract header (32 bits)
    header_bits = []
    for i in range(32):
        pos = positions[i]
        pixel_idx = pos // 3
        ch = pos % 3

        x = pixel_idx % w
        y = pixel_idx // w

        r, g, b = pixels[x, y]
        channels = [r, g, b]

        header_bits.append(channels[ch] & 1)

    data_length_bits = int.from_bytes(from_bits(header_bits), "big")

    # Extract the actual hidden data bits
    data_bits = []
    for i in range(32, 32 + data_length_bits):
        pos = positions[i]
        pixel_idx = pos // 3
        ch = pos % 3

        x = pixel_idx % w
        y = pixel_idx // w

        r, g, b = pixels[x, y]
        channels = [r, g, b]

        data_bits.append(channels[ch] & 1)

    return from_bits(data_bits)


# -----------------------------
# CLI MAIN FUNCTION (removed - now called from GUI app)
# -----------------------------
# The main() function has been removed as the steganography functions
# are now called directly from the tkinter GUI application (stego_app.py)
