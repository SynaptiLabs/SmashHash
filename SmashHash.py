import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os
from tkinter.font import Font


class SmashHashApp:
    def __init__(self, root):
        # Updated GUI title and labels
        self.root = root
        self.root.title("SmashHash 🛠️ - Encrypt or Decrypt Your Files")
        self.root.geometry("500x400")

        # Initial Selection - Encrypt or Decrypt
        self.label = tk.Label(root, text="Welcome to SmashHash! Choose what to do:")
        self.label.pack(pady=10)

        self.encrypt_button = tk.Button(root, text="Encrypt Text", command=self.encrypt_menu)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(root, text="Decrypt Text", command=self.decrypt_menu)
        self.decrypt_button.pack(pady=5)

        # Adding the Exit button
        self.exit_button = tk.Button(root, text="Exit", command=self.root.quit)
        self.exit_button.pack(pady=20)

        self.file_path = ""
        self.output_file = ""

    def encrypt_menu(self):
        self.clear_window()
        tk.Label(self.root, text="Select SmashHash Encryption Method").pack(pady=10)

        tk.Button(self.root, text="Hash Encryption", command=self.hash_menu).pack(pady=5)
        tk.Button(self.root, text="Caesar Cipher", command=self.caesar_menu_encrypt).pack(pady=5)

        tk.Button(self.root, text="Back", command=self.show_main_menu).pack(pady=10)  # Back button

        # Adding the Exit button
        self.exit_button = tk.Button(self.root, text="Exit", command=self.root.quit)
        self.exit_button.pack(pady=20)

    def decrypt_menu(self):
        self.clear_window()
        tk.Label(self.root, text="Select SmashHash Decryption Method").pack(pady=10)

        tk.Button(self.root, text="Caesar Cipher Decryption", command=self.caesar_menu_decrypt).pack(pady=5)

        tk.Button(self.root, text="Back", command=self.show_main_menu).pack(pady=10)  # Back button

        # Adding the Exit button
        self.exit_button = tk.Button(self.root, text="Exit", command=self.root.quit)
        self.exit_button.pack(pady=20)

    def hash_menu(self):
        self.clear_window()
        tk.Label(self.root, text="Select Hash Algorithm for SmashHash").pack(pady=10)

        tk.Button(self.root, text="MD5", command=lambda: self.hash_encrypt("MD5")).pack(pady=5)
        tk.Button(self.root, text="SHA-1", command=lambda: self.hash_encrypt("SHA-1")).pack(pady=5)
        tk.Button(self.root, text="SHA-256", command=lambda: self.hash_encrypt("SHA-256")).pack(pady=5)

        tk.Button(self.root, text="Back", command=self.encrypt_menu).pack(pady=10)  # Back button

        # Adding the Exit button
        self.exit_button = tk.Button(self.root, text="Exit", command=self.root.quit)
        self.exit_button.pack(pady=20)

    def hash_encrypt(self, hash_type):
        # Ask the user to select a file
        file_path = filedialog.askopenfilename()
        if not file_path:
            messagebox.showerror("Error", "No file selected.")
            return

        try:
            # List to store the hashed values of each line
            hashed_lines = []

            # Open the file and process it line by line
            with open(file_path, 'r') as file:
                for line in file:
                    line = line.strip()  # Remove any leading/trailing whitespace

                    # Hash the line based on the selected hash algorithm
                    if hash_type == "MD5":
                        hashed_value = hashlib.md5(line.encode()).hexdigest()
                    elif hash_type == "SHA-1":
                        hashed_value = hashlib.sha1(line.encode()).hexdigest()
                    elif hash_type == "SHA-256":
                        hashed_value = hashlib.sha256(line.encode()).hexdigest()

                    # Append the hashed line to the list
                    hashed_lines.append(hashed_value)

            # Generate a unique file name to avoid overwriting existing files
            base_filename = f"smashhash_{hash_type}_Data"
            output_file = self.increment_filename(base_filename)

            # Write the hashed lines to the output file
            with open(output_file, 'w') as output:
                for hashed_line in hashed_lines:
                    output.write(hashed_line + '\n')

            # Show a message indicating successful encryption
            self.show_result_message("SmashHash Encryption Complete",
                                     f"{hash_type} encryption completed line by line.\nFile saved as: {output_file}\n")

        except Exception as e:
            # Handle any errors that occur during file processing
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def caesar_menu_encrypt(self):
        self.clear_window()
        tk.Label(self.root, text="Enter Caesar Cipher Shift Value for SmashHash:").pack(pady=10)

        self.shift_entry = tk.Entry(self.root)
        self.shift_entry.pack(pady=5)

        tk.Button(self.root, text="Submit", command=self.caesar_encrypt).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.encrypt_menu).pack(pady=10)  # Back button

        # Adding the Exit button
        self.exit_button = tk.Button(self.root, text="Exit", command=self.root.quit)
        self.exit_button.pack(pady=20)

    def caesar_encrypt(self):
        shift_value = self.shift_entry.get()
        if not shift_value.isdigit():
            messagebox.showerror("Error", "Please enter a valid shift value.")
            return

        shift = int(shift_value)
        file_path = filedialog.askopenfilename()
        if not file_path:
            messagebox.showerror("Error", "No file selected.")
            return

        try:
            with open(file_path, 'r') as file:
                plaintext = file.read()

            encrypted_text = ''.join(
                chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else
                chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else char
                for char in plaintext)

            base_filename = f"smashhash_caesar_encryption_shift_{shift}_Data"
            output_file = self.increment_filename(base_filename)

            with open(output_file, 'w') as output:
                output.write(encrypted_text)

            self.show_result_message("Caesar Cipher SmashHash Complete",
                                     f"Caesar cipher encryption completed with shift {shift}.\nFile saved as: {output_file}\n")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def caesar_menu_decrypt(self):
        self.clear_window()
        tk.Label(self.root, text="Enter Caesar Cipher Shift Value for SmashHash:").pack(pady=10)

        self.shift_entry = tk.Entry(self.root)
        self.shift_entry.pack(pady=5)

        tk.Button(self.root, text="Submit", command=self.caesar_decrypt).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.decrypt_menu).pack(pady=10)  # Back button

        # Adding the Exit button
        self.exit_button = tk.Button(self.root, text="Exit", command=self.root.quit)
        self.exit_button.pack(pady=20)

    def caesar_decrypt(self):
        shift_value = self.shift_entry.get()
        if not shift_value.isdigit():
            messagebox.showerror("Error", "Please enter a valid shift value.")
            return

        shift = int(shift_value)
        file_path = filedialog.askopenfilename()
        if not file_path:
            messagebox.showerror("Error", "No file selected.")
            return

        try:
            with open(file_path, 'r') as file:
                encrypted_text = file.read()

            decrypted_text = ''.join(
                chr((ord(char) - 65 - shift) % 26 + 65) if char.isupper() else
                chr((ord(char) - 97 - shift) % 26 + 97) if char.islower() else char
                for char in encrypted_text)

            base_filename = f"smashhash_caesar_decryption_shift_{shift}_Data"
            output_file = self.increment_filename(base_filename)

            with open(output_file, 'w') as output:
                output.write(decrypted_text)

            self.show_result_message("Caesar Cipher SmashHash Decryption Complete",
                                     f"Caesar cipher decryption completed with shift {shift}.\nFile saved as: {output_file}\n")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def increment_filename(self, base_filename):
        counter = 1
        new_filename = base_filename
        while os.path.exists(f"{new_filename}.txt"):
            new_filename = f"{base_filename} {counter}"
            counter += 1
        return f"{new_filename}.txt"

    def show_result_message(self, title, message):
        self.clear_window()
        tk.Label(self.root, text=title, font=Font(size=14, weight='bold'), fg="blue").pack(pady=10)
        tk.Label(self.root, text=message, wraplength=400).pack(pady=10)
        tk.Button(self.root, text="Exit and View Result", command=self.exit_and_show_result).pack(pady=20)

    def exit_and_show_result(self):
        if self.output_file:
            os.startfile(self.output_file)
        self.root.quit()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_main_menu(self):
        self.clear_window()
        self.__init__(self.root)


if __name__ == "__main__":
    root = tk.Tk()
    app = SmashHashApp(root)
    root.mainloop()
