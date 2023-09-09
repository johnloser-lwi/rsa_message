from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import tkinter as tk
from tkinter.filedialog import askdirectory
from tkinter.filedialog import askopenfilename

import pyperclip

import base64

class rsa_message:
    def __init__(self):
        self.current_public_key = ""
        self.current_private_key = ""

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,  # RSA1024
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    def encrypt_message(self, public_key, message):
        try:
            
            message_bytes = message.encode('utf-8')
            ciphertext = public_key.encrypt(
                message_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )
            return ciphertext
        except:
            return "Failed to encrypt message!"

    def decrypt_message(self, private_key, ciphertext):
        try:
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )
            return plaintext.decode('utf-8')
        except:
            return "Invalid message!"

    def run_encrypt(self, msg=""):
        # open file dialoge to load public key
        public_key = None
        #tk.Tk().withdraw()
        if self.current_public_key == "":
            self.current_public_key = askopenfilename(title="Select a Public Key File", filetypes=[("Public Key Files", "*.pem")])
        try:
            with open(self.current_public_key, "rb") as f:
                    public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
        except:
            print("Invalid key file!")
            return ""
        if msg == "" : msg = input("Enter the message: ")
        encrypted_message = self.encrypt_message(public_key, msg)
        out = base64.b64encode(encrypted_message).decode('utf-8')
        print("Encrypted Message:", out)
        # copy message to clipboard
        pyperclip.copy(out)
        print("Message copied to clipboard")
        
        return out
        
    def run_decrypt(self, msg=""):
        # open file dialoge to load public key
        private_key = None
        #tk.Tk().withdraw()
        if self.current_private_key == "":
            self.current_private_key = askopenfilename(title="Select a Private Key File", filetypes=[("Private Key Files", "*.pem")])
        try:
            with open(self.current_private_key, "rb") as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
        except:
            print("Invalid key file!")
            return ""  
        if msg == "" : msg = input("Enter the message: ")
        decrypted_message = self.decrypt_message(private_key, base64.b64decode(msg))
        print("Decrypted Message:", decrypted_message)
        
        return decrypted_message
        
    def run_generate_key_pair(self):
        private_key, public_key = self.generate_key_pair()
        # open dialogue to select folder to save keys
        
        #tk.Tk().withdraw()
        folder = askdirectory(title="Select a folder to save keys")
        with open(folder + "/private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(folder + "/public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
    def reset_key_file_selections(self):
        self.current_private_key = ""
        self.current_public_key = ""


class RSA_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Messenger")
        self.app = rsa_message()
        
        self.message_input = tk.Text(root, width=50, wrap=tk.WORD, height=5)
        self.message_output = tk.Label(root, width=50, text="Encrypted/Decrypted Message", wraplength=300, justify="left")
        
        # Create buttons for each operation
        encrypt_button = tk.Button(root, text="Encrypt Message", command=self.run_encrypt)
        decrypt_button = tk.Button(root, text="Decrypt Message", command=self.run_decrypt)
        generate_key_button = tk.Button(root, text="Generate Key Pair", command=self.run_generate_key_pair)
        reset_button = tk.Button(root, text="Reset Key Selections", command=self.reset_key_file_selections)
        exit_button = tk.Button(root, text="Exit", command=root.quit)
        
        # Arrange buttons in a grid
        self.message_input.grid(row=1, column=0, columnspan=2, padx=10, pady=10)
        encrypt_button.grid(row=1, column=3, pady=10, padx=10)
        
        self.message_output.grid(row=2, column=0, columnspan=2, padx=10, pady=10)
        decrypt_button.grid(row=2, column=3, pady=10, padx=10)
        
        generate_key_button.grid(row=3, column=0, pady=10)
        reset_button.grid(row=3, column=1, pady=10)
        #exit_button.grid(row=4, column=0, pady=10)
    
    def run_encrypt(self):
        print("Running encryption...")
        # Implement your encryption code here
        res = self.app.run_encrypt(self.message_input.get())
        # set message output text
        if res != "" : self.message_output["text"] = "Copied to clipboard!"
        else : self.message_output["text"] = "Failed to encrypt message!"
    
    def run_decrypt(self):
        print("Running decryption...")
        # Implement your decryption code here
        # get message from clipboard
        msg = pyperclip.paste()
        res = self.app.run_decrypt(msg)
        if res != "" : self.message_output["text"] = res
        else : self.message_output["text"] = "Failed to decrypt message!"
    
    def run_generate_key_pair(self):
        print("Running key pair generation...")
        # Implement your key pair generation code here
        self.app.run_generate_key_pair()
    
    def reset_key_file_selections(self):
        print("Resetting key selections...")
        # Implement your key selection reset code here
        self.app.reset_key_file_selections()

if __name__ == "__main__":
    
    app = rsa_message()
    
    # while True:
    
    #     print("1. Encrypt Message\n2. Decrypt Message\n3. Generate Key Pair\n4. Reset Key Selections\n5. Exit")
    #     operation = input("Enter the operation(1/2/3/4/5): ")
        
    #     if operation == '1':
    #         app.run_encrypt()
    #     elif operation == '2':
    #         app.run_decrypt()
    #     elif operation == '3':
    #         app.run_generate_key_pair()
    #     elif operation == '4':
    #         app.reset_key_file_selections()
    #     elif operation == '5':
    #         break
    #     else:
    #         print("Invalid operation!")
            
    #     print("\n\n")
    root = tk.Tk()
    app = RSA_GUI(root)
    root.mainloop()
    
    print("Closed!")
    