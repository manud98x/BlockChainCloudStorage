import os
import tkinter as tk
from tkinter import filedialog, Listbox, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ecdsa import SigningKey, SECP256k1
from web3 import Web3
import json
from eth_utils import keccak, to_bytes

# Connect to local Ethereum blockchain (Ganache)
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

# Smart contract ABI and address (replace with actual values after deployment)
contract_address = "0x30c0304C1EbEb1051ABda36D26fb491be1e618D5"  # Deployed contract address

# Load contract ABI from the file
with open('artifacts/contracts/FileSharing.sol/FileSharing.json', 'r') as abi_file:
    contract_data = json.load(abi_file)
    contract_abi = contract_data['abi']  # Extract only the ABI

# Access contract
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Get default account to use (account[0])
account = w3.eth.accounts[0]

# Directories to store the encrypted files and signatures
ENCRYPTED_FILES_DIR = "encrypted_files"  # Use relative path
SIGNATURE_FILES_DIR = "signatures"  # Store signatures in the main directory

# Ensure directories exist
if not os.path.exists(ENCRYPTED_FILES_DIR):
    os.makedirs(ENCRYPTED_FILES_DIR)
if not os.path.exists(SIGNATURE_FILES_DIR):
    os.makedirs(SIGNATURE_FILES_DIR)

# AES Encryption Function
def encrypt_file(file_path, key):
    try:
        iv = os.urandom(16)  # Initialization vector (16 bytes)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext  # Return IV concatenated with ciphertext
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None

# AES Decryption Function
def decrypt_file(encrypted_data, key):
    try:
        iv = encrypted_data[:16]  # Extract the first 16 bytes as the IV
        ciphertext = encrypted_data[16:]  # The rest is the actual ciphertext
        
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
        
        # Store the signature and the key together in the signature file
        return signature + key  # Append the key to the signature
    except Exception as e:
        print(f"File signing failed: {e}")
        return None

# Convert string to bytes32
def str_to_bytes32(text):
    return Web3.toBytes(text.encode('utf-8')).ljust(32, b'\0')[:32]

# Function to upload file and its metadata to blockchain
def upload_file_to_blockchain(file_id, file_hash, file_name):
    try:
        tx_hash = contract.functions.uploadFile(file_id, file_hash, file_name).transact({'from': account})
        # Wait for transaction receipt with new method
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"File uploaded: {file_name}")
        return True
    except Exception as e:
        print(f"Error uploading file: {e}")
        return False

# Encrypt and Upload File Action
def encrypt_and_upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            # Step 1: Generate a new encryption key (AES 256-bit key)
            key = os.urandom(32)
            
            # Step 2: Encrypt the file
            encrypted_data = encrypt_file(file_path, key)
            
            if encrypted_data is None:
                status_label.config(text="Error during encryption")
                return

            # Save the encrypted file with a filename based on the file_id
            file_id = keccak(file_path.encode('utf-8'))  # Generate a unique file ID
            encrypted_file_name = f"encrypted_{file_id.hex()}"  # Save file with a unique name based on the file ID
            encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, encrypted_file_name)
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)

            # Step 3: Sign the file and save the key with the signature
            private_key = SigningKey.generate(curve=SECP256k1).to_string()
            signature = sign_file(file_path, private_key, key)  # Include the encryption key in the signature
            
            if signature is None:
                status_label.config(text="Error during signing")
                return

            # Save the signature using the encrypted file name, not the original file name
            signature_file_path = os.path.join(SIGNATURE_FILES_DIR, encrypted_file_name + ".sig")
            with open(signature_file_path, 'wb') as f:
                f.write(signature)

            # Step 4: Upload file metadata to blockchain
            file_hash = keccak(encrypted_file_path.encode('utf-8')).hex()  # Hash the encrypted file path as bytes

            # Convert file_id to bytes32
            file_id_bytes32 = to_bytes(file_id)
            
            # Upload to blockchain
            file_name = os.path.basename(file_path)
            if upload_file_to_blockchain(file_id_bytes32, file_hash, file_name):
                status_label.config(text=f"File {file_name} encrypted and uploaded successfully")
                display_uploaded_files()  # Update uploaded files list
            else:
                status_label.config(text="Error uploading file to blockchain")
        except Exception as e:
            print(f"Error: {e}")
            status_label.config(text="An error occurred")

# Function to fetch and display uploaded files
def display_uploaded_files():
    try:
        uploaded_files = contract.functions.getUploadedFiles().call()
        uploaded_files_list.delete(0, tk.END)  # Clear the listbox
        if uploaded_files:
            for file_id in uploaded_files:
                uploaded_files_list.insert(tk.END, f"File ID: {file_id.hex()}")
        else:
            uploaded_files_list.insert(tk.END, "No files uploaded yet.")
    except Exception as e:
        print(f"Error fetching uploaded files: {e}")
        uploaded_files_list.insert(tk.END, "Error fetching uploaded files.")

# Function to delete a file from local storage (encrypted file and signature)
def delete_file():
    selected_file = uploaded_files_list.get(tk.ACTIVE)
    if not selected_file:
        messagebox.showwarning("No File Selected", "Please select a file to delete.")
        return
    
    # Extract the file ID from the selected string (after "File ID: ")
    file_id_hex = selected_file.split("File ID: ")[1]
    
    # Map the file ID to the local file
    encrypted_file_name = f"encrypted_{file_id_hex}"
    encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, encrypted_file_name)
    signature_file_path = os.path.join(SIGNATURE_FILES_DIR, encrypted_file_name + ".sig")

    try:
        # Delete the encrypted file
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
            print(f"Deleted: {encrypted_file_path}")
        else:
            print(f"File not found: {encrypted_file_path}")

        # Delete the signature file
        if os.path.exists(signature_file_path):
            os.remove(signature_file_path)
            print(f"Deleted: {signature_file_path}")
        else:
            print(f"Signature not found: {signature_file_path}")

        # Remove the file from the listbox
        uploaded_files_list.delete(tk.ACTIVE)
        status_label.config(text="File and signature deleted successfully")
    except Exception as e:
        print(f"Error deleting file: {e}")
        status_label.config(text="Error deleting file")

# Function to download a file from the blockchain
def download_file():
    selected_file = uploaded_files_list.get(tk.ACTIVE)
    if not selected_file:
        messagebox.showwarning("No File Selected", "Please select a file to download.")
        return
    
    # Extract the file ID from the selected string (after "File ID: ")
    file_id_hex = selected_file.split("File ID: ")[1]
    file_id_bytes32 = bytes.fromhex(file_id_hex)

    try:
        # Retrieve the file hash (which is the encrypted file path) from the blockchain
        file_hash = contract.functions.downloadFile(file_id_bytes32).call({'from': account})
        
        # Map the file hash to the local file using the file ID (not the file_hash directly)
        encrypted_file_name = f"encrypted_{file_id_hex}"
        encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, encrypted_file_name)
        
        # Check if the file exists locally
        if not os.path.exists(encrypted_file_path):
            raise FileNotFoundError(f"No such file: '{encrypted_file_path}'")
        
        # Ask user to select where to save the decrypted file
        save_path = filedialog.asksaveasfilename(title="Save Decrypted File")
        if not save_path:
            return
        
        # Read the key from the signature file
        signature_file_path = os.path.join(SIGNATURE_FILES_DIR, encrypted_file_name + ".sig")
        with open(signature_file_path, 'rb') as f:
            signature_and_key = f.read()
            key = signature_and_key[-32:]  # The last 32 bytes represent the AES key
        
        # Read the encrypted content
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()

        # Decrypt the file
        decrypted_data = decrypt_file(encrypted_data, key)  # Extract the IV internally
        
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
