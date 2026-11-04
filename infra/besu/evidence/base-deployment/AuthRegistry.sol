// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice Minimal synthetic RP registry. Application signature verification is off-chain.
contract AuthRegistry {
    error InvalidStructure();
    error Unauthorized();
    error StateChanged();
    error MissingDependency();
    error InvalidState();
    error IdAlreadyUsed();

    struct RootRecord {
        string rootDid;
        address managementIdentity;
        bytes32 didDocumentDigest;
        string appKeyId;
        uint64 appKeyVersion;
        bytes appPublicKey;
    }

    RootRecord private fixedRoot;
    bytes32 public immutable instanceId;
    string public constant schemaVersion = "grad-auth-v1";
    bytes32 public immutable resourceId;
    bytes32 public immutable resourceOwner;

    constructor(RootRecord memory root, bytes32 instance, bytes32 resource, bytes32 owner) {
        if (bytes(root.rootDid).length == 0 || root.managementIdentity == address(0) ||
            root.didDocumentDigest == bytes32(0) || bytes(root.appKeyId).length == 0 ||
            root.appKeyVersion == 0 || instance == bytes32(0) || resource == bytes32(0) || owner == bytes32(0)) {
            revert InvalidStructure();
        }
        checkPublicKey(root.appPublicKey);
        fixedRoot = root;
        instanceId = instance;
        resourceId = resource;
        resourceOwner = owner;
    }

    function getRoot() external view returns (RootRecord memory) {
        return fixedRoot;
    }

    function checkPublicKey(bytes memory key) private pure {
        if (key.length != 65 || key[0] != 0x04) revert InvalidStructure();
        uint256 x;
        uint256 y;
        assembly ("memory-safe") {
            x := mload(add(key, 33))
            y := mload(add(key, 65))
        }
        uint256 p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
        uint256 b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;
        if (x >= p || y >= p || mulmod(y, y, p) != addmod(addmod(mulmod(mulmod(x, x, p), x, p), p - mulmod(3, x, p), p), b, p)) {
            revert InvalidStructure();
        }
    }
}
