
# Secure File Sharing System

## Overview

This is a decentralized, secure file sharing system built using **Tkinter** for the GUI, **Web3.py** to interact with the Ethereum blockchain (using **BuildBear** as the network), and **cryptography** libraries for file encryption and digital signatures. The system enables users to upload, share, and download encrypted files securely while leveraging smart contracts to manage access control on the blockchain.

The app supports key functionalities like uploading encrypted files to the blockchain, granting/revoking access to specific users, and downloading files, ensuring that only authorized users can access sensitive data.

## Features

- **Secure File Encryption**: Files are encrypted using AES-256 encryption before being uploaded.
- **File Uploading**: Upload files and store their metadata (file hash, encryption key) on the blockchain.
- **Grant and Revoke Access**: File owners can grant or revoke access to specific Ethereum addresses.
- **File Download**: Authorized users can download and decrypt the original file.
- **Private Key Login**: The user logs in by providing their Ethereum private key to perform transactions.
- **Access Control via Smart Contract**: Only authorized users can download or modify file access.

## Technology Stack

- **Python**: Main programming language used.
- **Tkinter**: Used for the graphical user interface (GUI).
- **Web3.py**: To interact with the Ethereum blockchain.
- **BuildBear**: A customized Ethereum test network for transaction processing.
- **Cryptography**: Used for AES encryption and RSA key management.
- **ECDSA**: For digital signing of files.

## Requirements

1. **Python 3.7+**
2. Install required dependencies using pip:
   ```bash
   pip install web3 cryptography pycryptodome ecdsa tkinter
   ```
3. **BuildBear Account**: You’ll need a BuildBear RPC endpoint URL to connect to the blockchain.
4. **Ethereum Account**: You’ll need an Ethereum private key to log in and interact with the blockchain.

## Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/secure-file-sharing
cd secure-file-sharing
```

### Step 2: Launch the Application

Run the Python script:

```bash
python implementation.py
```

### Step 2: Login with Private Key

Upon launching the app, a prompt will appear asking for your Ethereum private key. This key will be used to authenticate and interact with the blockchain.

## User Guide

### 1. Encrypt and Upload File
- Click on the **"Encrypt and Upload File"** button.
- Select the file you want to upload. The file will be encrypted and uploaded to the blockchain.

### 2. Grant Access to a File
- Select a file from the list of uploaded files.
- Click **"Grant Access"**.
- Enter the recipient's Ethereum address and confirm.

### 3. Revoke Access to a File
- Select a file from the list of uploaded files.
- Click **"Revoke Access"**.
- Enter the recipient's Ethereum address and confirm.

### 4. Download a File
- Select a file from the list of uploaded files.
- Click **"Download File"**.
- If you are authorized, the file will be downloaded and decrypted.

## Error Handling

- If a non-owner tries to grant or revoke access, the system will display an error message.
- If someone without permission tries to download a file, they will receive an access denied error.

