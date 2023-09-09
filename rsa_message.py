from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from tkinter import Tk
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

    def run_encrypt(self):
        # open file dialoge to load public key
        public_key = None
        Tk().withdraw()
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
            return
        msg = input("Enter the message: ")
        encrypted_message = self.encrypt_message(public_key, msg)
        print("Encrypted Message:", base64.b64encode(encrypted_message).decode('utf-8'))
        # copy message to clipboard
        pyperclip.copy(base64.b64encode(encrypted_message).decode('utf-8'))
        print("Message copied to clipboard")
        
    def run_decrypt(self):
        # open file dialoge to load public key
        private_key = None
        Tk().withdraw()
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
            return    
        msg = input("Enter the message: ")
        decrypted_message = self.decrypt_message(private_key, base64.b64decode(msg))
        print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    
    app = rsa_message()
    
    while True:
    
        print("1. Encrypt Message\n2. Decrypt Message\n3. Generate Key Pair\n4. Reset Key Selections\n5. Exit")
        operation = input("Enter the operation(1/2/3/4/5): ")
        
        if operation == '1':
            app.run_encrypt()
        elif operation == '2':
            app.run_decrypt()
        elif operation == '3':
            private_key, public_key = generate_key_pair()
            # open dialogue to select folder to save keys
            
            Tk().withdraw()
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
        elif operation == '4':
            app.current_public_key = ""
            app.current_private_key = ""
        elif operation == '5':
            break
        else:
            print("Invalid operation!")
            
        print("\n\n")
