import os
import tkinter as tk
import tkinter.ttk as ttk
import json
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ecdsa import SigningKey, SECP256k1
from web3 import Web3
from eth_account import Account
from eth_utils import keccak
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# BuildBear endpoint (Replace with your BuildBear RPC URL)
buildbear_rpc_url = "https://rpc.buildbear.io/indirect-doctoroctopus-a938176d"
w3 = Web3(Web3.HTTPProvider(buildbear_rpc_url))

def load_abi(file_path):
    with open(file_path, 'r') as abi_file:
        return json.load(abi_file)

# Check connection to BuildBear
if w3.is_connected():
    print("Connected to BuildBear Custom Network!")
else:
    raise ConnectionError("Failed to connect to BuildBear Custom Network")

# Smart contract address and ABI (based on provided ABI)
contract_address = Web3.to_checksum_address("0x020fa4b5e7704e7fdaa2b22f161920ec3df79e21")
contract_abi = load_abi('Contract\contract_abi.json')
# Access contract using the checksum address and correct ABI
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Directories to store the encrypted files and signatures
ENCRYPTED_FILES_DIR = "encrypted_files"
SIGNATURE_FILES_DIR = "signatures"

# Ensure directories exist
if not os.path.exists(ENCRYPTED_FILES_DIR):
    os.makedirs(ENCRYPTED_FILES_DIR)
if not os.path.exists(SIGNATURE_FILES_DIR):
    os.makedirs(SIGNATURE_FILES_DIR)

# Login Dialog to Enter Private Key
class LoginDialog(simpledialog.Dialog):
    def body(self, master):
        tk.Label(master, text="Enter Private Key:").grid(row=0)
        self.private_key_entry = tk.Entry(master, show="*")  # Mask the private key
        self.private_key_entry.grid(row=0, column=1)
        return self.private_key_entry

    def apply(self):
        self.private_key = self.private_key_entry.get()

# Prompt login dialog
def prompt_login():
    login = LoginDialog(window)
    return login.private_key

# AES Encryption Function
def encrypt_file(file_path, key):
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None

# AES Decryption Function
def decrypt_file(encrypted_data, key):
    try:
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# ECDSA File Signing
def sign_file(file_path, private_key, key):
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        sk = SigningKey.from_string(private_key, curve=SECP256k1)
        signature = sk.sign(file_content)
        return signature + key  # Append the key to the signature
    except Exception as e:
        print(f"File signing failed: {e}")
        return None

# RSA Encryption for Key Sharing
def encrypt_key_for_recipient(public_key_str, key):
    try:
        public_key = RSA.import_key(public_key_str)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher_rsa.encrypt(key)
        return encrypted_key
    except Exception as e:
        print(f"Key encryption failed: {e}")
        return None

# Function to send a transaction
def send_transaction(tx):
    try:
        tx['nonce'] = w3.eth.get_transaction_count(account.address)
        tx['gasPrice'] = w3.eth.gas_price
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Transaction successful with hash: {tx_hash.hex()}")
        return receipt
    except Exception as e:
        print(f"Transaction failed: {e}")
        return None

# Function to upload file and its metadata to blockchain
def upload_file_to_blockchain(file_id_hex, file_hash, file_name, encrypted_key):
    try:
        file_id_bytes32 = Web3.to_bytes(hexstr=file_id_hex)
        nonce = w3.eth.get_transaction_count(account.address)
        gas_price = w3.eth.gas_price

        tx = contract.functions.uploadFile(file_id_bytes32, file_hash, file_name, encrypted_key).build_transaction({
            'from': account.address,
            'gas': 1000000,
            'gasPrice': gas_price,
            'nonce': nonce,
            'chainId': w3.eth.chain_id
        })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt:
            print(f"File {file_name} uploaded successfully. Transaction hash: {receipt.transactionHash.hex()}")
            return True
    except Exception as e:
        print(f"Error uploading file: {e}")
    return False

def grant_access():
    selected_file = file_tree.focus()
    if not selected_file:
        messagebox.showwarning("No File Selected", "Please select a file to grant access.")
        return

    recipient_address = simpledialog.askstring("Grant Access", "Enter Recipient Address:")
    if recipient_address:
        file_id_hex = file_tree.item(selected_file)['values'][0]
        try:
            # Get the file metadata (file name, owner address)
            file_metadata = contract.functions.getFileMetadata(bytes.fromhex(file_id_hex)).call()
            file_owner = Web3.to_checksum_address(file_metadata[1])  # The second element is the owner

            # Ensure the current user is the file owner
            user_address = Web3.to_checksum_address(account.address)

            # Log for debugging purposes
            print(f"File Owner: {file_owner}")
            print(f"Your Address: {user_address}")

            if file_owner != user_address:
                messagebox.showerror("Error", "Only the file owner can grant access to the file!")
                return

            # Proceed with granting access if the current user is the file owner
            tx = contract.functions.grantAccess(recipient_address, bytes.fromhex(file_id_hex)).build_transaction({
                'from': account.address,
                'gas': 300000,
                'gasPrice': w3.eth.gas_price,
                'nonce': w3.eth.get_transaction_count(account.address),
                'chainId': w3.eth.chain_id
            })
            receipt = send_transaction(tx)
            if receipt:
                print(f"Access granted for file {file_id_hex} to {recipient_address}")
                messagebox.showinfo("Success", "Access granted successfully!")
        except Exception as e:
            print(f"Grant access failed: {e}")
            messagebox.showerror("Error", f"Grant access failed: {e}")


# Function to revoke access
def revoke_access():
    selected_file = file_tree.focus()
    if not selected_file:
        messagebox.showwarning("No File Selected", "Please select a file to revoke access.")
        return

    recipient_address = simpledialog.askstring("Revoke Access", "Enter Recipient Address:")
    if recipient_address:
        file_id_hex = file_tree.item(selected_file)['values'][0]
        try:
            # Get the contract owner and ensure checksummed addresses
            contract_owner = Web3.to_checksum_address(contract.functions.owner().call())
            user_address = Web3.to_checksum_address(account.address)

            if contract_owner != user_address:
                messagebox.showerror("Error", "Only the owner can revoke access to the file!")
                return

            tx = contract.functions.revokeAccess(recipient_address, bytes.fromhex(file_id_hex)).build_transaction({
                'from': account.address,
                'gas': 300000,
                'gasPrice': w3.eth.gas_price,
                'nonce': w3.eth.get_transaction_count(account.address),
                'chainId': w3.eth.chain_id
            })
            receipt = send_transaction(tx)
            if receipt:
                print(f"Access revoked for file {file_id_hex} from {recipient_address}")
                messagebox.showinfo("Success", "Access revoked successfully!")
        except Exception as e:
            print(f"Revoke access failed: {e}")
            messagebox.showerror("Error", f"Revoke access failed: {e}")


# Function to download a file
def download_file():
    selected_file = file_tree.focus()
    if not selected_file:
        messagebox.showwarning("No File Selected", "Please select a file to download.")
        return

    file_id_hex = file_tree.item(selected_file)['values'][0]
    try:
        can_access = contract.functions.canAccess(account.address, bytes.fromhex(file_id_hex)).call()
        if not can_access:
            messagebox.showerror("Error", "You do not have access to this file!")
            return

        file_hash, encrypted_key = contract.functions.downloadFile(bytes.fromhex(file_id_hex)).call({'from': account.address})

        encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, f"encrypted_{file_id_hex}")
        if not os.path.exists(encrypted_file_path):
            raise FileNotFoundError(f"No such file: {encrypted_file_path}")

        decrypted_file_path = filedialog.asksaveasfilename(title="Save Decrypted File")
        if not decrypted_file_path:
            return

        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_file(encrypted_data, bytes.fromhex(encrypted_key))

        if decrypted_data:
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)
            messagebox.showinfo("Success", f"File downloaded and saved to {decrypted_file_path}")
        else:
            messagebox.showerror("Error", "Decryption failed.")
    except Exception as e:
        print(f"Download failed: {e}")
        messagebox.showerror("Error", f"Download failed: {e}")

# Function to encrypt and upload the file
def encrypt_and_upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            key = os.urandom(32)  # AES 256-bit key
            encrypted_data = encrypt_file(file_path, key)
            
            if encrypted_data is None:
                status_label.config(text="Error during encryption")
                return

            file_id = keccak(file_path.encode('utf-8'))
            encrypted_file_name = f"encrypted_{file_id.hex()}"
            encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, encrypted_file_name)
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)

            private_key = SigningKey.generate(curve=SECP256k1).to_string()
            signature = sign_file(file_path, private_key, key)
            
            if signature is None:
                status_label.config(text="Error during signing")
                return

            signature_file_path = os.path.join(SIGNATURE_FILES_DIR, encrypted_file_name + ".sig")
            with open(signature_file_path, 'wb') as f:
                f.write(signature)

            file_hash = keccak(encrypted_file_path.encode('utf-8')).hex()
            encrypted_key = key.hex()

            if upload_file_to_blockchain(file_id.hex(), file_hash, os.path.basename(file_path), encrypted_key):
                status_label.config(text=f"File {file_path} encrypted and uploaded successfully")
                display_uploaded_files()
            else:
                status_label.config(text="Error uploading file to blockchain")
        except Exception as e:
            print(f"Error: {e}")
            status_label.config(text="An error occurred")

# Fetch and display uploaded files
def display_uploaded_files():
    try:
        uploaded_files = contract.functions.getUploadedFiles().call()
        for i in file_tree.get_children():
            file_tree.delete(i)
        if uploaded_files:
            for file_id in uploaded_files:
                file_metadata = contract.functions.getFileMetadata(file_id).call()
                file_name, owner_address = file_metadata
                file_tree.insert("", "end", values=(file_id.hex(), file_name, owner_address))
        else:
            status_label.config(text="No files uploaded yet.")
    except Exception as e:
        print(f"Error fetching uploaded files: {e}")
        status_label.config(text="Error fetching uploaded files.")

# Create tkinter window
window = tk.Tk()
window.title("Secure File Sharing System")
window.geometry("800x500")  # Set the window size

# Prompt user to enter their private key
private_key = prompt_login()

# If the user didn't provide a key, exit the application
if not private_key:
    messagebox.showerror("Error", "Private key is required to login!")
    window.destroy()
else:
    try:
        account = Account.from_key(private_key)
        print(f"Using account: {account.address}")
    except Exception as e:
        messagebox.showerror("Error", f"Invalid Private Key: {e}")
        window.destroy()

# Frame for buttons
button_frame = tk.Frame(window)
button_frame.pack(pady=20)

# Add buttons and labels
encrypt_button = tk.Button(button_frame, text="Encrypt and Upload File", width=25, command=encrypt_and_upload_file)
encrypt_button.grid(row=0, column=0, padx=10)

download_button = tk.Button(button_frame, text="Download File", width=25, command=download_file)
download_button.grid(row=0, column=1, padx=10)

grant_button = tk.Button(button_frame, text="Grant Access", width=25, command=grant_access)
grant_button.grid(row=1, column=0, padx=10, pady=10)

revoke_button = tk.Button(button_frame, text="Revoke Access", width=25, command=revoke_access)
revoke_button.grid(row=1, column=1, padx=10, pady=10)

status_label = tk.Label(window, text="", font=("Arial", 12))
status_label.pack(pady=10)

# Create a Treeview widget to show file name and owner address
columns = ("file_id", "file_name", "owner_address")
file_tree = ttk.Treeview(window, columns=columns, show='headings', height=10)
file_tree.heading("file_id", text="File ID")
file_tree.heading("file_name", text="File Name")
file_tree.heading("owner_address", text="Owner Address")
file_tree.column("file_id", width=200)
file_tree.column("file_name", width=250)
file_tree.column("owner_address", width=300)
file_tree.pack(pady=10)

# Initially load the uploaded files when the program starts
display_uploaded_files()

# Run tkinter event loop
window.mainloop()
