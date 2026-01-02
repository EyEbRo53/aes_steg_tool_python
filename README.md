# Steganography & Encryption Desktop Application

A desktop application that securely hides sensitive information within image files using advanced cryptography and steganography techniques.

## 🔐 Features

- **Image Upload**: Select any image file as a carrier for hidden data
- **Message Encryption**: Secure messages using 128-bit AES encryption with Galois/Counter Mode (GCM)
- **LSB Steganography**: Hide encrypted data in image pixels using Least Significant Bit (LSB) technique
- **Password Protection**: Use custom passwords to generate encryption keys
- **File Safety**: Automatically saves encoded images in PNG format
- **Easy Retrieval**: Decode hidden messages with the original password

## 🚀 How to Use

### Encoding (Hiding a Message)

1. **Launch the Application**

   ```bash
   python3 stego_app.py
   ```

2. **Upload an Image**: Click the upload button to select your cover image

3. **Enter Password**: Type a secure password in the password field

4. **Type Your Message**: Enter the text message you want to hide

5. **Click Encode**: The application will:
   - Encrypt your message using 128-bit AES-GCM encryption with your password as the key
   - Hide the encrypted message in the image's pixels using LSB steganography
   - Save the result as a PNG file in your chosen location

### Decoding (Retrieving a Message)

1. **Launch the Application**

   ```bash
   python3 stego_app.py
   ```

2. **Upload Encoded Image**: Select the image containing the hidden message

3. **Enter Password**: Type the same password used during encoding

4. **Click Decode**: The application will extract and decrypt your hidden message

## 🔧 Technical Details

### Encryption

- **Algorithm**: AES-128 in Galois/Counter Mode (GCM)
- **Key Derivation**: Password-based key generation
- **Security**: Authenticated encryption with associated data (AEAD)
- **Key Size**: 128 bits (16 bytes)

### Steganography

- **Technique**: Least Significant Bit (LSB) Embedding
- **Method**: The encrypted message is embedded into the least significant bit of each color channel (R, G, B) in image pixels
- **Randomization**: Embedding positions are randomized using a seed derived from the password, making the payload harder to detect
- **Overhead**: 32-bit header to store the message length for accurate extraction

### File Format

- **Input**: Supports common image formats (JPEG, PNG, BMP, etc.)
- **Output**: Always saves as PNG to preserve data integrity and prevent lossy compression

## 📋 Requirements

See `requirements.txt` for all dependencies:

- **Pillow**: Image processing and manipulation
- **tkinter**: GUI framework (usually pre-installed with Python)

## 💻 Installation

1. Clone or download the project
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python3 stego_app.py
   ```

## ⚠️ Security Notes

- Use strong, memorable passwords for encryption
- The security of your hidden data depends on your password strength
- LSB steganography is not visible to the naked eye but can be detected with steganalysis tools
- Always keep backups of important encoded images

## 📁 Project Structure

- `stego_app.py`: Main GUI application
- `Stego.py`: Core steganography functions (LSB embedding/extraction)
- `aes_gcm.py`: AES-128-GCM encryption implementation
- `requirements.txt`: Python dependencies

## 🎓 Educational Purpose

This project implements steganography and encryption for educational purposes, demonstrating cryptographic concepts and data hiding techniques.

---
