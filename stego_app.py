import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk


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
        text_frame = tk.Frame(parent, bg="#2c2c2c")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)

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
        file_path = filedialog.askopenfilename(
            title="Select an image",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("All files", "*.*"),
            ],
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

        try:
            # TODO: Implement steganography encoding
            messagebox.showinfo(
                "Encode",
                f"Message '{message[:50]}{'...' if len(message) > 50 else ''}' would be encoded into the image.",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {str(e)}")

    def decode_message(self):
        if not self.image_path:
            messagebox.showwarning("Warning", "Please upload an image first.")
            return

        try:
            # TODO: Implement steganography decoding
            decoded_message = "Decoded message would appear here."
            self.message_text.delete("1.0", tk.END)
            self.message_text.insert("1.0", decoded_message)
            self.message_text.config(fg="#fff")
            messagebox.showinfo("Decode", "Message decoded successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {str(e)}")


def main():
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
