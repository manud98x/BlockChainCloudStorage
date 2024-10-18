// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureFileSharing {
    struct File {
        string fileName;
        address uploader;
        string fileHash;
        string encryptedKey;
    }

    mapping(bytes32 => File) private files;
    mapping(bytes32 => mapping(address => bool)) private accessRights;
    bytes32[] private uploadedFiles;

    // Events
    event FileUploaded(bytes32 indexed fileId, address indexed uploader, string fileName);
    event AccessGranted(bytes32 indexed fileId, address indexed user);
    event AccessRevoked(bytes32 indexed fileId, address indexed user);
    event FileDownloaded(bytes32 indexed fileId, address indexed user);

    // Function to upload a file
    function uploadFile(
        bytes32 fileId,
        string memory fileHash,
        string memory fileName,
        string memory encryptedKey
    ) public {
        require(bytes(fileHash).length > 0, "File hash cannot be empty");
        require(bytes(fileName).length > 0, "File name cannot be empty");

        File memory newFile = File({
            fileName: fileName,
            uploader: msg.sender,
            fileHash: fileHash,
            encryptedKey: encryptedKey
        });

        files[fileId] = newFile;
        uploadedFiles.push(fileId);

        // Grant access to the uploader by default
        accessRights[fileId][msg.sender] = true;

        emit FileUploaded(fileId, msg.sender, fileName);
    }

    // Function to grant access to a user
    function grantAccess(address user, bytes32 fileId) public {
        require(files[fileId].uploader == msg.sender, "Only the uploader can grant access");
        require(user != address(0), "Invalid user address");

        accessRights[fileId][user] = true;
        emit AccessGranted(fileId, user);
    }

    // Function to revoke access from a user
    function revokeAccess(address user, bytes32 fileId) public {
        require(files[fileId].uploader == msg.sender, "Only the uploader can revoke access");
        require(user != address(0), "Invalid user address");

        accessRights[fileId][user] = false;
        emit AccessRevoked(fileId, user);
    }

    // Function to check if a user has access to a file
    function canAccess(address user, bytes32 fileId) public view returns (bool) {
        return accessRights[fileId][user];
    }

    // Function to download a file (returns file hash and encrypted key)
    function downloadFile(bytes32 fileId) public view returns (string memory, string memory) {
        require(accessRights[fileId][msg.sender], "You do not have access to this file");

        File memory file = files[fileId];
        return (file.fileHash, file.encryptedKey);
    }

    // Function to get all uploaded file IDs
    function getUploadedFiles() public view returns (bytes32[] memory) {
        return uploadedFiles;
    }

    // Function to retrieve file metadata (name and uploader)
    function getFileMetadata(bytes32 fileId) public view returns (string memory, address) {
        require(bytes(files[fileId].fileHash).length > 0, "File does not exist");
        File memory file = files[fileId];
        return (file.fileName, file.uploader);
    }

    // Function to check if a file is uploaded
    function isFileUploaded(bytes32 fileId) public view returns (bool) {
        return bytes(files[fileId].fileHash).length > 0;
    }

    // Function to get the owner/uploader of a file
    function owner() public view returns (address) {
        return msg.sender;
    }
}
