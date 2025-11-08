// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CipherChatIdentity {
    struct UserKey {
        bytes32 fingerprint; // hash of ECDH public key
        uint256 updatedAt;
    }

    mapping(address => UserKey) public userKeys;

    event KeyRegistered(address indexed user, bytes32 fingerprint, uint256 time);

    function registerKey(bytes memory pubKey) public {
        bytes32 fingerprint = keccak256(pubKey);
        userKeys[msg.sender] = UserKey(fingerprint, block.timestamp);
        emit KeyRegistered(msg.sender, fingerprint, block.timestamp);
    }

    function getKey(address user) public view returns (bytes32) {
        return userKeys[user].fingerprint;
    }
}