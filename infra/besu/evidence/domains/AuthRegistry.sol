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

    uint8 private constant PENDING = 1;
    uint8 private constant ACTIVE = 2;
    uint8 private constant REVOKED = 4;

    struct DomainInput {
        string domainId;
        string domainDid;
        address administrator;
        address registrar;
    }

    struct DomainRecord {
        string domainId;
        string domainDid;
        address administrator;
        address registrar;
        string[] identityIssuers;
        bytes32 currentCertificationId;
        uint8 status;
        uint64 revision;
    }

    struct IdentityInput {
        string subjectId;
        string domainId;
        uint8 kind;
        address managementIdentity;
        bytes32 didDocumentDigest;
        string appKeyId;
        uint64 appKeyVersion;
        bytes appPublicKey;
        bytes32 accountCommitment;
    }

    struct IdentityRecord {
        IdentityInput identity;
        address registrar;
        uint8 status;
        uint64 revision;
    }

    struct IssuerScope {
        string id;
        uint64 appKeyVersion;
        string[] credentialTypes;
        string[] claimNames;
    }

    struct CertificationInput {
        string certificationId;
        string domainId;
        uint64 issuerKeyVersion;
        bytes32 digest;
        uint64 nbf;
        uint64 exp;
        IssuerScope[] identityIssuers;
    }

    struct DomainCertificationRecord {
        CertificationInput certification;
        string domainDid;
        address administrator;
        address registrar;
        uint8 status;
        uint64 revision;
    }

    mapping(bytes32 => DomainRecord) private domains;
    mapping(bytes32 => IdentityRecord) private identities;
    mapping(bytes32 => DomainCertificationRecord) private certifications;
    mapping(address => bytes32) private managementSubjects;

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
        managementSubjects[root.managementIdentity] = idHash(root.rootDid);
    }

    function getRoot() external view returns (RootRecord memory) {
        return fixedRoot;
    }

    function idHash(string memory id) private pure returns (bytes32) {
        return sha256(bytes(id));
    }

    function same(string memory a, string memory b) private pure returns (bool) {
        return idHash(a) == idHash(b);
    }

    function onlyRoot() private view {
        if (msg.sender != fixedRoot.managementIdentity) revert Unauthorized();
    }

    /// @dev T confirms control proofs off-chain. This entry admits only domains and issuers.
    function bootstrapDomain(DomainInput calldata input, IdentityInput calldata domainIdentity, IdentityInput[] calldata issuers) external {
        onlyRoot();
        bytes32 key = idHash(input.domainId);
        if (domains[key].status != 0) revert IdAlreadyUsed();
        if (bytes(input.domainId).length == 0 || bytes(input.domainDid).length == 0 ||
            input.administrator == address(0) || input.registrar == address(0) ||
            issuers.length == 0 || issuers.length > 8 || domainIdentity.kind != 1 ||
            !same(domainIdentity.subjectId, input.domainDid) || !same(domainIdentity.domainId, input.domainId)) revert InvalidStructure();
        storeIdentity(domainIdentity, msg.sender);
        DomainRecord storage d = domains[key];
        d.domainId = input.domainId;
        d.domainDid = input.domainDid;
        d.administrator = input.administrator;
        d.registrar = input.registrar;
        d.status = PENDING;
        d.revision = 1;
        for (uint256 i; i < issuers.length; ++i) {
            if (issuers[i].kind != 2 || !same(issuers[i].domainId, input.domainId) ||
                (i > 0 && !less(issuers[i-1].subjectId, issuers[i].subjectId))) revert InvalidStructure();
            storeIdentity(issuers[i], msg.sender);
            d.identityIssuers.push(issuers[i].subjectId);
        }
    }

    function registerDomainCertification(CertificationInput calldata input, uint64 expectedDomainRevision, bytes32 expectedCurrentCertificationId) external {
        onlyRoot();
        bytes32 key = idHash(input.certificationId);
        if (certifications[key].status != 0) revert IdAlreadyUsed();
        DomainRecord storage d = domains[idHash(input.domainId)];
        if (d.status == 0) revert MissingDependency();
        if (d.revision != expectedDomainRevision || d.currentCertificationId != expectedCurrentCertificationId) revert StateChanged();
        // This slice implements the first certification only. Renewal/replacement has no entry.
        if (d.status != PENDING || d.currentCertificationId != bytes32(0)) revert InvalidState();
        if (bytes(input.certificationId).length == 0 || input.digest == bytes32(0) || input.issuerKeyVersion != fixedRoot.appKeyVersion ||
            input.identityIssuers.length != d.identityIssuers.length) revert InvalidStructure();
        checkInterval(input.nbf, input.exp);
        for (uint256 i; i < input.identityIssuers.length; ++i) {
            IssuerScope calldata scope = input.identityIssuers[i];
            IdentityRecord storage issuer = identities[idHash(scope.id)];
            if (!same(scope.id, d.identityIssuers[i]) || issuer.status != ACTIVE || issuer.identity.kind != 2 ||
                !same(issuer.identity.domainId, input.domainId) || issuer.identity.appKeyVersion != scope.appKeyVersion) revert InvalidStructure();
            checkSet(scope.credentialTypes, 64);
            checkSet(scope.claimNames, 64);
        }
        DomainCertificationRecord storage c = certifications[key];
        c.certification = input;
        c.domainDid = d.domainDid;
        c.administrator = d.administrator;
        c.registrar = d.registrar;
        c.status = ACTIVE;
        c.revision = 1;
        d.currentCertificationId = key;
        d.status = ACTIVE;
        ++d.revision;
    }

    function getDomain(bytes32 id) external view returns (DomainRecord memory) {
        if (domains[id].status == 0) revert MissingDependency();
        return domains[id];
    }

    function getIdentity(bytes32 id) external view returns (IdentityRecord memory) {
        if (identities[id].status == 0) revert MissingDependency();
        return identities[id];
    }

    function getDomainCertification(bytes32 id) external view returns (DomainCertificationRecord memory) {
        if (certifications[id].status == 0) revert MissingDependency();
        return certifications[id];
    }

    function storeIdentity(IdentityInput calldata input, address registrar) private {
        bytes32 key = idHash(input.subjectId);
        if (identities[key].status != 0 || managementSubjects[input.managementIdentity] != bytes32(0)) revert IdAlreadyUsed();
        if (bytes(input.subjectId).length == 0 || bytes(input.domainId).length == 0 ||
            input.managementIdentity == address(0) || input.didDocumentDigest == bytes32(0) || input.accountCommitment == bytes32(0) || input.appKeyVersion == 0) revert InvalidStructure();
        bytes memory prefix = bytes(string.concat(input.subjectId, "#"));
        bytes memory keyId = bytes(input.appKeyId);
        if (keyId.length <= prefix.length) revert InvalidStructure();
        for (uint256 i; i < prefix.length; ++i) { if (prefix[i] != keyId[i]) revert InvalidStructure(); }
        checkPublicKey(input.appPublicKey);
        identities[key] = IdentityRecord(input, registrar, ACTIVE, 1);
        managementSubjects[input.managementIdentity] = key;
    }

    function activeDomain(string memory domainId) private view returns (DomainRecord storage d) {
        d = domains[idHash(domainId)];
        if (d.status == 0) revert MissingDependency();
        if (d.status != ACTIVE || identities[idHash(d.domainDid)].status != ACTIVE) revert InvalidState();
        DomainCertificationRecord storage c = certifications[d.currentCertificationId];
        if (c.status != ACTIVE || c.certification.nbf > block.timestamp || block.timestamp >= c.certification.exp) revert InvalidState();
    }

    function checkInterval(uint64 nbf, uint64 exp) private view {
        if (nbf >= exp || nbf > block.timestamp || block.timestamp >= exp) revert InvalidStructure();
    }

    function less(string memory a, string memory b) private pure returns (bool) {
        bytes memory aa = bytes(a); bytes memory bb = bytes(b);
        uint256 n = aa.length < bb.length ? aa.length : bb.length;
        for (uint256 i; i < n; ++i) { if (aa[i] != bb[i]) return uint8(aa[i]) < uint8(bb[i]); }
        return aa.length < bb.length;
    }

    function checkSet(string[] calldata values, uint256 limit) private pure {
        if (values.length == 0 || values.length > limit) revert InvalidStructure();
        for (uint256 i; i < values.length; ++i) {
            bytes memory value = bytes(values[i]);
            if (value.length == 0 || (i > 0 && !less(values[i-1], values[i]))) revert InvalidStructure();
            for (uint256 j; j < value.length; ++j) { if (value[j] == 0x2a) revert InvalidStructure(); }
        }
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
