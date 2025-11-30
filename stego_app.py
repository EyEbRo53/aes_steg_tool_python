import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import hashlib
import subprocess
import os
import sys
from pathlib import Path
from aes_gcm import aes_gcm_encrypt, aes_gcm_decrypt, generate_iv
from Stego import embed_data_lsb, extract_data_lsb


def native_file_dialog(
    mode="open", title="Select file", filetypes=None, initialdir=None
):
    """
    Use OS native file dialog.
    - Windows: Uses tkinter's filedialog (which uses native Windows file picker)
    - Linux: Uses zenity (GNOME) or kdialog (KDE)
    Returns None if cancelled.
    mode: "open" or "save"
    """
    # Windows: tkinter's filedialog already uses native Windows file picker
    if sys.platform == "win32":
        if mode == "open":
            return filedialog.askopenfilename(
                title=title, filetypes=filetypes, initialdir=initialdir
            )
        else:
            return filedialog.asksaveasfilename(
                title=title,
                filetypes=filetypes,
                initialdir=initialdir,
                defaultextension=".png",
            )

    # Linux: Try zenity (GNOME/GTK)
    try:
        if mode == "open":
            cmd = ["zenity", "--file-selection", "--title", title]
            if filetypes:
                # Build file filter for zenity: "Description | *.ext1 *.ext2"
                # zenity expects: --file-filter="Description | *.ext1 *.ext2"
                for desc, exts in filetypes:
                    if exts != "*.*":
                        # Keep the pattern as-is: "*.png *.jpg *.jpeg"
                        filter_pattern = exts.strip()
                        cmd.extend(["--file-filter", f"{desc} | {filter_pattern}"])
                    else:
                        cmd.extend(["--file-filter", f"{desc} | *"])
        else:  # save
            cmd = ["zenity", "--file-selection", "--title", title, "--save"]
            if filetypes:
                for desc, exts in filetypes:
                    if exts != "*.*":
                        filter_pattern = exts.strip()
                        cmd.extend(["--file-filter", f"{desc} | {filter_pattern}"])
                    else:
                        cmd.extend(["--file-filter", f"{desc} | *"])

        if initialdir:
            cmd.extend(["--filename", initialdir])

        result = subprocess.run(cmd, capture_output=True, text=True)
        # Exit code 1 means user cancelled, 0 means success
        if result.returncode == 0:
            path = result.stdout.strip()
            return path if path else None
        else:
            return None  # User cancelled
    except FileNotFoundError:
        pass

    # Try kdialog (KDE)
    try:
        start_dir = initialdir or os.getcwd()
        if mode == "open":
            cmd = ["kdialog", "--getopenfilename", start_dir]
            if filetypes:
                # kdialog format: "*.ext1 *.ext2|Description"
                patterns = []
                for desc, exts in filetypes:
                    if exts != "*.*":
                        patterns.append(exts.strip())
                if patterns:
                    cmd.append("|".join(patterns))
        else:  # save
            cmd = ["kdialog", "--getsavefilename", start_dir]
            if filetypes:
                patterns = []
                for desc, exts in filetypes:
                    if exts != "*.*":
                        patterns.append(exts.strip())
                if patterns:
                    cmd.append("|".join(patterns))

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            path = result.stdout.strip()
            return path if path else None
        else:
            return None  # User cancelled
    except FileNotFoundError:
        pass

    # No native dialog available - return None instead of falling back
    # This prevents the old tkinter dialog from appearing
    return None


class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Stego Encryptor")
        self.root.configure(bg="#1f1f1f")

        window_width = 1200
        window_height = 700
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")

        self.current_image = None
        self.image_path = None

        self.create_widgets()

    def create_widgets(self):
        container = tk.Frame(self.root, bg="#2c2c2c", relief=tk.FLAT)
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        left_panel = tk.Frame(container, bg="#3c3c3c", relief=tk.FLAT)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 1))

        right_panel = tk.Frame(container, bg="#2c2c2c", relief=tk.FLAT)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.create_left_panel(left_panel)

        self.create_right_panel(right_panel)

    def create_left_panel(self, parent):
        upload_frame = tk.Frame(parent, bg="#3c3c3c")
        upload_frame.pack(pady=20)

        upload_button = tk.Button(
            upload_frame,
            text="📁 Upload Image",
            command=self.upload_image,
            bg="#555",
            fg="#e0e0e0",
            font=("Inter", 11, "normal"),
            relief=tk.FLAT,
            padx=16,
            pady=10,
            cursor="hand2",
            activebackground="#666",
            activeforeground="#e0e0e0",
        )
        upload_button.pack()

        preview_container = tk.Frame(parent, bg="#3c3c3c")
        preview_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        preview_frame = tk.Frame(preview_container, bg="#444", relief=tk.FLAT)
        preview_frame.place(
            relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=1.0, relheight=0.7
        )

        self.preview_text = tk.Label(
            preview_frame,
            text="Preview",
            bg="#444",
            fg="#bbb",
            font=("Inter", 14, "normal"),
        )
        self.preview_text.pack(expand=True)

        self.preview_label = tk.Label(preview_frame, bg="#444", relief=tk.FLAT)

        button_frame = tk.Frame(parent, bg="#3c3c3c")
        button_frame.pack(pady=20)

        encode_button = tk.Button(
            button_frame,
            text="🔒 Encode",
            command=self.encode_message,
            bg="#e6e6e6",
            fg="#111",
            font=("Inter", 11, "bold"),
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2",
            activebackground="#ccc",
            activeforeground="#111",
        )
        encode_button.pack(side=tk.LEFT, padx=7)

        decode_button = tk.Button(
            button_frame,
            text="🔓 Decode",
            command=self.decode_message,
            bg="#e6e6e6",
            fg="#111",
            font=("Inter", 11, "bold"),
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor="hand2",
            activebackground="#ccc",
            activeforeground="#111",
        )
        decode_button.pack(side=tk.LEFT, padx=7)

    def create_right_panel(self, parent):
        # Password field at the top
        password_frame = tk.Frame(parent, bg="#2c2c2c")
        password_frame.pack(fill=tk.X, padx=40, pady=(40, 20))

        password_label = tk.Label(
            password_frame,
            text="Password:",
            bg="#2c2c2c",
            fg="#e0e0e0",
            font=("Inter", 12, "normal"),
        )
        password_label.pack(side=tk.LEFT, padx=(0, 10))

        self.password_entry = tk.Entry(
            password_frame,
            bg="#444",
            fg="#fff",
            font=("Inter", 12, "normal"),
            relief=tk.FLAT,
            show="*",
            insertbackground="#fff",
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)

        # Message text area
        text_frame = tk.Frame(parent, bg="#2c2c2c")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=(0, 40))

        self.message_text = tk.Text(
            text_frame,
            bg="#444",
            fg="#fff",
            font=("Inter", 15, "normal"),
            relief=tk.FLAT,
            padx=12,
            pady=12,
            wrap=tk.WORD,
            insertbackground="#fff",
        )
        self.message_text.pack(fill=tk.BOTH, expand=True)

        self.message_text.insert("1.0", "Enter your secret message here...")
        self.message_text.config(fg="#999")
        self.message_text.bind("<FocusIn>", self.on_text_focus_in)
        self.message_text.bind("<FocusOut>", self.on_text_focus_out)

    def on_text_focus_in(self, event):
        if (
            self.message_text.get("1.0", "end-1c")
            == "Enter your secret message here..."
        ):
            self.message_text.delete("1.0", tk.END)
            self.message_text.config(fg="#fff")

    def on_text_focus_out(self, event):
        if not self.message_text.get("1.0", "end-1c").strip():
            self.message_text.insert("1.0", "Enter your secret message here...")
            self.message_text.config(fg="#999")

    def upload_image(self):
        file_path = native_file_dialog(
            mode="open",
            title="Select an image",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("All files", "*.*"),
            ],
            initialdir=os.path.expanduser("~"),
        )

        if file_path:
            try:
                self.image_path = file_path

                img = Image.open(file_path)

                self.root.update_idletasks()
                preview_frame_width = self.root.winfo_width() // 2 - 80
                preview_frame_height = int((self.root.winfo_height() - 200) * 0.7)

                target_width = min(
                    preview_frame_width, int(preview_frame_height * 16 / 9)
                )
                target_height = min(
                    preview_frame_height, int(preview_frame_width * 9 / 16)
                )

                img.thumbnail((target_width, target_height), Image.Resampling.LANCZOS)

                self.current_image = ImageTk.PhotoImage(img)

                self.preview_label.config(image=self.current_image, bg="#444")
                self.preview_label.image = self.current_image  # Keep a reference
                self.preview_label.pack(expand=True)
                self.preview_text.pack_forget()

            except Exception as e:
                messagebox.showerror("Error", f"Failed to load image: {str(e)}")

    def get_message(self):
        """Get the message from textarea, handling placeholder text."""
        message = self.message_text.get("1.0", "end-1c").strip()
        if message == "Enter your secret message here...":
            return ""
        return message

    def encode_message(self):
        if not self.image_path:
            messagebox.showwarning("Warning", "Please upload an image first.")
            return

        message = self.get_message()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to encode.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        try:
            # Convert message to bytes
            message_bytes = message.encode("utf-8")

            # Derive AES key from password (SHA256 hash, take first 16 bytes)
            password_hash = hashlib.sha256(password.encode()).digest()
            aes_key = password_hash[:16]

            # Generate IV (12 bytes for GCM)
            iv = generate_iv(12)

            # Encrypt message with AES-GCM
            ciphertext, tag = aes_gcm_encrypt(aes_key, iv, message_bytes)

            # Format: IV (12 bytes) + ciphertext + tag (16 bytes)
            encrypted_data = iv + ciphertext + tag

            # Ask for output file location
            output_path = native_file_dialog(
                mode="save",
                title="Save encoded image",
                filetypes=[
                    ("PNG files", "*.png"),
                    ("All files", "*.*"),
                ],
                initialdir=(
                    os.path.dirname(self.image_path)
                    if self.image_path
                    else os.path.expanduser("~")
                ),
            )

            if not output_path:
                return

            # Ensure output path has .png extension
            if not output_path.lower().endswith((".png", ".jpg", ".jpeg", ".bmp")):
                output_path = output_path + ".png"

            # Embed encrypted data into image using steganography
            # Use password as stego_key for position randomization
            embed_data_lsb(self.image_path, output_path, encrypted_data, password)

            messagebox.showinfo(
                "Success",
                f"Message encoded successfully!\nSaved to: {output_path}",
            )

            # Update preview to show the encoded image
            self.image_path = output_path
            # Refresh preview without file dialog
            try:
                img = Image.open(output_path)
                self.root.update_idletasks()
                preview_frame_width = self.root.winfo_width() // 2 - 80
                preview_frame_height = int((self.root.winfo_height() - 200) * 0.7)
                target_width = min(
                    preview_frame_width, int(preview_frame_height * 16 / 9)
                )
                target_height = min(
                    preview_frame_height, int(preview_frame_width * 9 / 16)
                )
                img.thumbnail((target_width, target_height), Image.Resampling.LANCZOS)
                self.current_image = ImageTk.PhotoImage(img)
                self.preview_label.config(image=self.current_image, bg="#444")
                self.preview_label.image = self.current_image
                self.preview_label.pack(expand=True)
                self.preview_text.pack_forget()
            except Exception:
                pass  # If preview update fails, continue anyway

        except ValueError as e:
            messagebox.showerror(
                "Error",
                f"Encoding failed: {str(e)}\n\nImage may be too small for the message.",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {str(e)}")

    def decode_message(self):
        if not self.image_path:
            messagebox.showwarning("Warning", "Please upload an image first.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        try:
            # Extract data from image using steganography
            # Use password as stego_key for position randomization
            extracted_data = extract_data_lsb(self.image_path, password)

            if len(extracted_data) < 28:  # Minimum: 12 (IV) + 0 (ciphertext) + 16 (tag)
                raise ValueError("No valid data found in image or incorrect password.")

            # Parse: IV (first 12 bytes), tag (last 16 bytes), ciphertext (middle)
            iv = extracted_data[:12]
            tag = extracted_data[-16:]
            ciphertext = extracted_data[12:-16]

            # Derive AES key from password (same as encoding)
            password_hash = hashlib.sha256(password.encode()).digest()
            aes_key = password_hash[:16]

            # Decrypt message with AES-GCM
            plaintext, tag_valid = aes_gcm_decrypt(aes_key, iv, ciphertext, b"", tag)

            if not tag_valid:
                messagebox.showerror(
                    "Error",
                    "Decryption failed: Invalid authentication tag.\n\nThis may indicate:\n- Incorrect password\n- Image does not contain encoded data\n- Image was corrupted",
                )
                return

            # Display decrypted message
            decoded_message = plaintext.decode("utf-8")
            self.message_text.delete("1.0", tk.END)
            self.message_text.insert("1.0", decoded_message)
            self.message_text.config(fg="#fff")
            messagebox.showinfo("Success", "Message decoded successfully!")

        except UnicodeDecodeError:
            messagebox.showerror(
                "Error",
                "Decryption failed: Could not decode message as text.\n\nThis may indicate:\n- Incorrect password\n- Image does not contain encoded data",
            )
        except ValueError as e:
            messagebox.showerror("Error", f"Decoding failed: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {str(e)}")


def main():
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
