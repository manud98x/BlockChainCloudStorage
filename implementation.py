import os
import tkinter as tk
from tkinter import filedialog, Listbox, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ecdsa import SigningKey, SECP256k1
from web3 import Web3
from eth_account import Account
from eth_utils import keccak, to_bytes

# Alchemy Sepolia endpoint
alchemy_url = "https://eth-sepolia.g.alchemy.com/v2/QkX3a5mEbFcJgXQqQ-8RkcT3jV7wqOhJ"
w3 = Web3(Web3.HTTPProvider(alchemy_url))

# Check connection to Sepolia
if w3.is_connected():
    print("Connected to Sepolia Testnet")
else:
    raise ConnectionError("Failed to connect to Sepolia Testnet")

# Smart contract address and ABI
contract_address = Web3.to_checksum_address("0x7da26dc83cc86bacad8c72fdc7e5f17536ce2de9")

# Replace with the correct ABI you provided
contract_abi = [
    {"inputs":[],"stateMutability":"nonpayable","type":"constructor"},
    {"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"fileId","type":"bytes32"},{"indexed":True,"internalType":"address","name":"user","type":"address"}],"name":"AccessGranted","type":"event"},
    {"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"fileId","type":"bytes32"},{"indexed":True,"internalType":"address","name":"user","type":"address"}],"name":"AccessRevoked","type":"event"},
    {"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"fileId","type":"bytes32"},{"indexed":True,"internalType":"address","name":"user","type":"address"}],"name":"FileDownloaded","type":"event"},
    {"anonymous":False,"inputs":[{"indexed":True,"internalType":"bytes32","name":"fileId","type":"bytes32"},{"indexed":True,"internalType":"address","name":"uploader","type":"address"},{"indexed":False,"internalType":"string","name":"fileName","type":"string"}],"name":"FileUploaded","type":"event"},
    {"inputs":[{"internalType":"address","name":"user","type":"address"},{"internalType":"bytes32","name":"fileId","type":"bytes32"}],"name":"canAccess","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"bytes32","name":"fileId","type":"bytes32"}],"name":"downloadFile","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"getUploadedFiles","outputs":[{"internalType":"bytes32[]","name":"","type":"bytes32[]"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"address","name":"user","type":"address"},{"internalType":"bytes32","name":"fileId","type":"bytes32"}],"name":"grantAccess","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"bytes32","name":"fileId","type":"bytes32"}],"name":"isFileUploaded","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"address","name":"user","type":"address"},{"internalType":"bytes32","name":"fileId","type":"bytes32"}],"name":"revokeAccess","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"bytes32","name":"fileId","type":"bytes32"},{"internalType":"string","name":"fileHash","type":"string"},{"internalType":"string","name":"fileName","type":"string"}],"name":"uploadFile","outputs":[],"stateMutability":"nonpayable","type":"function"}
]

# Access contract using the checksum address and correct ABI
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Use your Sepolia account's private key
private_key = "ef86c9aed631ef25ad290c977899a7dde92c0b365acfbd589caa2ed3ac44795b"  # Replace with your private key
account = Account.from_key(private_key)

# Log account information
print(f"Using account: {account.address}")

# Directories to store the encrypted files and signatures
ENCRYPTED_FILES_DIR = "encrypted_files"
SIGNATURE_FILES_DIR = "signatures"

# Ensure directories exist
if not os.path.exists(ENCRYPTED_FILES_DIR):
    os.makedirs(ENCRYPTED_FILES_DIR)
if not os.path.exists(SIGNATURE_FILES_DIR):
    os.makedirs(SIGNATURE_FILES_DIR)

# AES Encryption Function
def encrypt_file(file_path, key):
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        print(f"File {file_path} encrypted successfully.")
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
        print("Decryption successful.")
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
        print(f"File {file_path} signed successfully.")
        return signature + key  # Append the key to the signature
    except Exception as e:
        print(f"File signing failed: {e}")
        return None

# Convert string to bytes32
def str_to_bytes32(text):
    return Web3.toBytes(text.encode('utf-8')).ljust(32, b'\0')[:32]

# Function to send a transaction
def send_transaction(tx):
    try:
        tx['nonce'] = w3.eth.get_transaction_count(account.address)
        tx['gasPrice'] = w3.eth.gas_price
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Transaction successful with hash: {tx_hash.hex()}")
        return receipt
    except Exception as e:
        print(f"Transaction failed: {e}")
        return None

# Function to upload file and its metadata to blockchain
def upload_file_to_blockchain(file_id, file_hash, file_name):
    try:
        nonce = w3.eth.get_transaction_count(account.address)
        gas_price = w3.eth.gas_price
        file_id_bytes32 = Web3.to_bytes(hexstr=keccak(file_name.encode('utf-8')).hex())

        print(f"Uploading file with file_id: {file_id_bytes32} and file_hash: {file_hash}")

        tx = contract.functions.uploadFile(file_id_bytes32, file_hash, file_name).build_transaction({
            'from': account.address,
            'gas': 3000000,
            'gasPrice': gas_price,
            'nonce': nonce,
            'chainId': w3.eth.chain_id
        })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt:
            print(f"File {file_name} uploaded successfully. Transaction hash: {receipt.transactionHash.hex()}")
            return True
    except Exception as e:
        print(f"Error uploading file: {e}")
    return False


def revoke_file_access(file_id):
    try:
        # Convert the file ID to bytes32 if necessary
        file_id_bytes32 = Web3.to_bytes(hexstr=file_id)

        # Get the current nonce and gas price (increase the gas price to speed up the transaction)
        nonce = w3.eth.get_transaction_count(account.address)
        gas_price = w3.eth.to_wei('30', 'gwei')  # Correct method to convert Gwei to Wei

        print(f"Nonce: {nonce}, Gas price: {gas_price} wei")

        # Build the transaction to revoke access to the file
        tx = contract.functions.revokeAccess(account.address, file_id_bytes32).build_transaction({
            'from': account.address,
            'gas': 3000000,  # Increased gas limit (adjust as needed)
            'gasPrice': gas_price,
            'nonce': nonce,
            'chainId': w3.eth.chain_id  # Sepolia's chain ID (11155111)
        })

        # Sign and send the transaction
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

        print(f"Transaction sent. Tx hash: {tx_hash.hex()}")

        # Wait for the transaction receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)  # Increase timeout to 300 seconds
        if receipt:
            print(f"File access revoked successfully. Transaction hash: {receipt.transactionHash.hex()}")
            return True
    except Exception as e:
        print(f"Error revoking access: {e}")
    return False



# Encrypt and Upload File Action
def encrypt_and_upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            key = os.urandom(32)
            encrypted_data = encrypt_file(file_path, key)
            
            if encrypted_data is None:
                status_label.config(text="Error during encryption")
                return

            file_id = keccak(file_path.encode('utf-8'))
            encrypted_file_name = f"encrypted_{file_id.hex()}"
            encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, encrypted_file_name)
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
            print(f"Encrypted file saved at {encrypted_file_path}")

            private_key = SigningKey.generate(curve=SECP256k1).to_string()
            signature = sign_file(file_path, private_key, key)
            
            if signature is None:
                status_label.config(text="Error during signing")
                return

            signature_file_path = os.path.join(SIGNATURE_FILES_DIR, encrypted_file_name + ".sig")
            with open(signature_file_path, 'wb') as f:
                f.write(signature)
            print(f"Signature saved at {signature_file_path}")

            file_hash = keccak(encrypted_file_path.encode('utf-8')).hex()
            file_id_bytes32 = to_bytes(file_id)

            if upload_file_to_blockchain(file_id_bytes32, file_hash, os.path.basename(file_path)):
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
        uploaded_files_list.delete(0, tk.END)
        if uploaded_files:
            for file_id in uploaded_files:
                uploaded_files_list.insert(tk.END, f"File ID: {file_id.hex()}")
        else:
            uploaded_files_list.insert(tk.END, "No files uploaded yet.")
    except Exception as e:
        print(f"Error fetching uploaded files: {e}")
        uploaded_files_list.insert(tk.END, "Error fetching uploaded files.")

# Delete a file from local storage and revoke access on the blockchain
def delete_file():
    selected_file = uploaded_files_list.get(tk.ACTIVE)
    if not selected_file:
        messagebox.showwarning("No File Selected", "Please select a file to delete.")
        return

    file_id_hex = selected_file.split("File ID: ")[1]
    encrypted_file_name = f"encrypted_{file_id_hex}"
    encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, encrypted_file_name)
    signature_file_path = os.path.join(SIGNATURE_FILES_DIR, encrypted_file_name + ".sig")

    try:
        # Step 1: Revoke file access on the blockchain
        if revoke_file_access(file_id_hex):
            print(f"Access revoked for file ID: {file_id_hex}")

            # Step 2: Delete the file and signature locally
            if os.path.exists(encrypted_file_path):
                os.remove(encrypted_file_path)
                print(f"Deleted encrypted file: {encrypted_file_path}")
            else:
                print(f"Encrypted file not found: {encrypted_file_path}")

            if os.path.exists(signature_file_path):
                os.remove(signature_file_path)
                print(f"Deleted signature file: {signature_file_path}")
            else:
                print(f"Signature file not found: {signature_file_path}")

            uploaded_files_list.delete(tk.ACTIVE)
            status_label.config(text="File and signature deleted successfully")
        else:
            status_label.config(text="Failed to revoke access on blockchain")
    except Exception as e:
        print(f"Error deleting file: {e}")
        status_label.config(text="Error deleting file")

# Download a file from the blockchain
def download_file():
    selected_file = uploaded_files_list.get(tk.ACTIVE)
    if not selected_file:
        messagebox.showwarning("No File Selected", "Please select a file to download.")
        return

    file_id_hex = selected_file.split("File ID: ")[1]
    file_id_bytes32 = bytes.fromhex(file_id_hex)

    try:
        file_hash = contract.functions.downloadFile(file_id_bytes32).call({'from': account.address})
        encrypted_file_name = f"encrypted_{file_id_hex}"
        encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, encrypted_file_name)

        if not os.path.exists(encrypted_file_path):
            raise FileNotFoundError(f"No such file: '{encrypted_file_path}'")

        save_path = filedialog.asksaveasfilename(title="Save Decrypted File")
        if not save_path:
            return

        signature_file_path = os.path.join(SIGNATURE_FILES_DIR, encrypted_file_name + ".sig")
        with open(signature_file_path, 'rb') as f:
            signature_and_key = f.read()
            key = signature_and_key[-32:]

        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_file(encrypted_data, key)

        if decrypted_data:
            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            status_label.config(text=f"File downloaded and saved to {save_path}")
        else:
            status_label.config(text="Error during decryption")
    except Exception as e:
        print(f"Error downloading file: {e}")
        status_label.config(text="Error downloading the file")

# Create tkinter window
window = tk.Tk()
window.title("Secure File Sharing System")

# Add buttons and labels
encrypt_button = tk.Button(window, text="Encrypt and Upload File", command=encrypt_and_upload_file)
encrypt_button.pack()

download_button = tk.Button(window, text="Download Selected File", command=download_file)
download_button.pack()

delete_button = tk.Button(window, text="Delete Selected File", command=delete_file)
delete_button.pack()

status_label = tk.Label(window, text="")
status_label.pack()

# Add a listbox to show uploaded files
uploaded_files_list = Listbox(window, height=10, width=50)
uploaded_files_list.pack()

# Initially load the uploaded files when the program starts
display_uploaded_files()

# Run tkinter event loop
window.mainloop()
