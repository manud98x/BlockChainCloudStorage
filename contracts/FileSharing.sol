// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileSharing {
    mapping(address => mapping(bytes32 => bool)) private accessPermissions;
    mapping(bytes32 => string) private fileHashes;
    mapping(bytes32 => address) private fileOwners;
    bytes32[] private uploadedFiles;  // Array to store file IDs

    address public owner;

    event FileUploaded(bytes32 indexed fileId, address indexed uploader, string fileName);
    event AccessGranted(bytes32 indexed fileId, address indexed user);
    event AccessRevoked(bytes32 indexed fileId, address indexed user);
    event FileDownloaded(bytes32 indexed fileId, address indexed user);  // New event for file downloads

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the contract owner can perform this action");
        _;
    }

    modifier onlyFileOwner(bytes32 fileId) {
        require(fileOwners[fileId] == msg.sender, "Only the file owner can perform this action");
        _;
    }

    // Grant access to a user for a specific file
    function grantAccess(address user, bytes32 fileId) external onlyFileOwner(fileId) {
        accessPermissions[user][fileId] = true;
        emit AccessGranted(fileId, user);
    }

    // Upload a file's metadata to the contract
    function uploadFile(bytes32 fileId, string memory fileHash, string memory fileName) external {
        require(!isFileUploaded(fileId), "File with the same ID already uploaded");
        fileHashes[fileId] = fileHash;
        fileOwners[fileId] = msg.sender;
        accessPermissions[msg.sender][fileId] = true;  // File owner has access to their file by default
        uploadedFiles.push(fileId);  // Add the file ID to the list of uploaded files
        emit FileUploaded(fileId, msg.sender, fileName);
    }

    // Function to download a file by its file ID
    function downloadFile(bytes32 fileId) external returns (string memory) {
        require(canAccess(msg.sender, fileId), "Access denied");
        emit FileDownloaded(fileId, msg.sender);  // Emit an event when a file is downloaded
        return fileHashes[fileId];  // Return the file hash (in practice, the off-chain encrypted file reference)
    }

    // Check if a file with the given ID has already been uploaded
    function isFileUploaded(bytes32 fileId) public view returns (bool) {
        return bytes(fileHashes[fileId]).length > 0;
    }

    // Check if a user has access to the file
    function canAccess(address user, bytes32 fileId) public view returns (bool) {
        return accessPermissions[user][fileId];
    }

    // Revoke access to a file from a user
    function revokeAccess(address user, bytes32 fileId) external onlyFileOwner(fileId) {
        accessPermissions[user][fileId] = false;
        emit AccessRevoked(fileId, user);
    }

    // Function to return all uploaded file IDs
    function getUploadedFiles() external view returns (bytes32[] memory) {
        return uploadedFiles;
    }

    // Transfer contract ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be the zero address");
        owner = newOwner;
    }
}
