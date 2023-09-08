from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,  # RSA1024
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def encrypt_message(public_key, message):
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

def decrypt_message(private_key, ciphertext):
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

def run_encrypt():
    # open file dialoge to load public key
    public_key = None
    from tkinter import Tk
    from tkinter.filedialog import askopenfilename
    Tk().withdraw()
    filename = askopenfilename(title="Select a Public Key File", filetypes=[("Public Key Files", "*.pem")])
    with open(filename, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    msg = input("Enter the message: ")
    encrypted_message = encrypt_message(public_key, msg)
    print("Encrypted Message:", base64.b64encode(encrypted_message).decode('utf-8'))
    # copy message to clipboard
    import pyperclip
    pyperclip.copy(base64.b64encode(encrypted_message).decode('utf-8'))
    print("Message copied to clipboard")
    
def run_decrypt():
    # open file dialoge to load public key
    private_key = None
    from tkinter import Tk
    from tkinter.filedialog import askopenfilename
    Tk().withdraw()
    filename = askopenfilename(title="Select a Private Key File", filetypes=[("Private Key Files", "*.pem")])
    with open(filename, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    
    msg = input("Enter the message: ")
    decrypted_message = decrypt_message(private_key, base64.b64decode(msg))
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    print("1. Encrypt Message\n2. Decrypt Message\n3. Generate Key Pair\n")
    operation = input("Enter the operation(1/2/3): ")
    
    if operation == '1':
        run_encrypt()
    elif operation == '2':
        run_decrypt()
    elif operation == '3':
        private_key, public_key = generate_key_pair()
        # open dialogue to select folder to save keys
        from tkinter import Tk
        from tkinter.filedialog import askdirectory
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
            
    # wait for user to press enter
    input("Press Enter to exit...")
