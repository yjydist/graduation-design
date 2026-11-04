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
    bytes32 public immutable taskDomain;
    bytes32 public immutable taskCreator;
    bytes32 public immutable genesisHash;

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

    struct CredentialInput {
        string credentialId;
        string issuer;
        string subject;
        uint64 issuerKeyVersion;
        uint64 appKeyVersion;
        string credentialType;
        bytes32 digest;
        uint64 nbf;
        uint64 exp;
    }

    struct CredentialRecord {
        CredentialInput credential;
        uint8 status;
        uint64 revision;
    }

    mapping(bytes32 => CredentialRecord) private credentials;

    struct TaskInput {
        bytes32 taskId;
        bytes32 deploymentId;
        bytes32 creator;
        string principalDomain;
        string authorizationMode;
        bytes32 taskSpecDigest;
        bytes32 resourceId;
        bytes32 creatorCredentialId;
        uint64 creatorKeyVersion;
        uint64 nbf;
        uint64 exp;
    }

    struct TaskRecord { TaskInput task; uint8 status; uint64 revision; }

    struct GrantInput {
        bytes32 grantId;
        string schemaVersion;
        bytes32 deploymentId;
        bytes32 parentId;
        bytes32 parentDigest;
        bytes32 rootId;
        bytes32 taskId;
        string authorizationMode;
        string principalDomain;
        bytes32 issuer;
        bytes32 grantee;
        uint64 issuerKeyVersion;
        uint64 granteeKeyVersion;
        bytes32 issuerCredentialId;
        bytes32 granteeCredentialId;
        bytes32 resourceId;
        uint64 nbf;
        uint64 exp;
        uint8 remainingDepth;
        bytes32 digest;
    }

    struct GrantRecord { GrantInput grant; uint8 status; uint64 revision; }
    mapping(bytes32 => TaskRecord) private tasks;
    mapping(bytes32 => GrantRecord) private grants;

    constructor(RootRecord memory root, bytes32 instance, bytes32 resource, bytes32 owner, bytes32 trustedGenesis, bytes32 creatorDomain, bytes32 creatorSubject) {
        if (bytes(root.rootDid).length == 0 || root.managementIdentity == address(0) ||
            root.didDocumentDigest == bytes32(0) || bytes(root.appKeyId).length == 0 ||
            root.appKeyVersion == 0 || instance == bytes32(0) || resource == bytes32(0) || owner == bytes32(0) ||
            trustedGenesis == bytes32(0) || creatorDomain == bytes32(0) || creatorSubject == bytes32(0)) {
            revert InvalidStructure();
        }
        checkPublicKey(root.appPublicKey);
        fixedRoot = root;
        instanceId = instance;
        resourceId = resource;
        resourceOwner = owner;
        genesisHash = trustedGenesis;
        taskDomain = creatorDomain;
        taskCreator = creatorSubject;
        managementSubjects[root.managementIdentity] = idHash(root.rootDid);
    }

    function getRoot() external view returns (RootRecord memory) {
        return fixedRoot;
    }

    /// @dev The six ASCII string fields use the same key order and encodings as JCS.
    function deploymentId() public view returns (bytes32) {
        return sha256(bytes(string.concat(
            '{"chainId":"', decimal(block.chainid), '","genesisHash":"0x', hexBytes(abi.encodePacked(genesisHash)),
            '","instanceId":"', hexBytes(abi.encodePacked(instanceId)), '","registryAddress":"0x', hexBytes(abi.encodePacked(address(this))),
            '","runtimeCodeHash":"0x', hexBytes(abi.encodePacked(address(this).codehash)), '","schemaVersion":"', schemaVersion, '"}'
        )));
    }

    function decimal(uint256 value) private pure returns (string memory) {
        if (value == 0) return "0";
        uint256 n = value; uint256 len;
        while (n > 0) { ++len; n /= 10; }
        bytes memory out = new bytes(len);
        while (value > 0) { out[--len] = bytes1(uint8(48 + value % 10)); value /= 10; }
        return string(out);
    }

    function hexBytes(bytes memory value) private pure returns (string memory) {
        bytes memory chars = "0123456789abcdef";
        bytes memory out = new bytes(value.length * 2);
        for (uint256 i; i < value.length; ++i) { out[2*i] = chars[uint8(value[i]) >> 4]; out[2*i+1] = chars[uint8(value[i]) & 15]; }
        return string(out);
    }

    function idHash(string memory id) private pure returns (bytes32) {
        return sha256(bytes(id));
    }

    function same(string memory a, string memory b) private pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
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

    function registerIdentity(IdentityInput calldata input) external {
        DomainRecord storage d = activeDomain(input.domainId);
        if (msg.sender != d.registrar) revert Unauthorized();
        if (input.kind < 3 || input.kind > 5 || input.appKeyVersion != 1) revert InvalidStructure();
        storeIdentity(input, msg.sender);
    }

    function registerCredential(CredentialInput calldata input) external {
        bytes32 key = idHash(input.credentialId);
        if (credentials[key].status != 0) revert IdAlreadyUsed();
        IdentityRecord storage issuer = identities[idHash(input.issuer)];
        IdentityRecord storage subject = identities[idHash(input.subject)];
        if (issuer.status == 0 || subject.status == 0) revert MissingDependency();
        if (msg.sender != issuer.identity.managementIdentity) revert Unauthorized();
        if (issuer.status != ACTIVE || subject.status != ACTIVE) revert InvalidState();
        if (issuer.identity.kind != 2 || subject.identity.kind < 3 || !same(issuer.identity.domainId, subject.identity.domainId) ||
            issuer.identity.appKeyVersion != input.issuerKeyVersion || subject.identity.appKeyVersion != input.appKeyVersion ||
            bytes(input.credentialId).length == 0 || input.digest == bytes32(0)) revert InvalidStructure();
        DomainRecord storage d = activeDomain(subject.identity.domainId);
        requireIssuerScope(d, input.issuer, input.issuerKeyVersion, input.credentialType);
        checkInterval(input.nbf, input.exp);
        credentials[key] = CredentialRecord(input, ACTIVE, 1);
    }

    function getCredential(bytes32 id) external view returns (CredentialRecord memory) {
        if (credentials[id].status == 0) revert MissingDependency();
        return credentials[id];
    }

    function registerTask(TaskInput calldata input) external {
        if (tasks[input.taskId].status != 0) revert IdAlreadyUsed();
        IdentityRecord storage creator = activeIdentity(input.creator);
        if (msg.sender != creator.identity.managementIdentity || input.creator != taskCreator || idHash(input.principalDomain) != taskDomain) revert Unauthorized();
        if (input.deploymentId != deploymentId() || input.taskId == bytes32(0) || input.taskSpecDigest == bytes32(0) ||
            input.resourceId != resourceId || !same(input.principalDomain, creator.identity.domainId) || !same(input.authorizationMode, "RESOURCE_PREAUTHORIZED")) revert InvalidStructure();
        CredentialRecord storage c = validCredential(input.creatorCredentialId, input.creator, input.creatorKeyVersion);
        checkInterval(input.nbf, input.exp);
        if (input.nbf < c.credential.nbf || input.exp > c.credential.exp) revert InvalidStructure();
        tasks[input.taskId] = TaskRecord(input, ACTIVE, 1);
    }

    function registerGrant(GrantInput calldata input) external {
        bytes32 key = input.grantId;
        if (grants[key].status != 0) revert IdAlreadyUsed();
        TaskRecord storage t = tasks[input.taskId];
        if (t.status == 0) revert MissingDependency();
        if (t.status != ACTIVE || t.task.nbf > block.timestamp || block.timestamp >= t.task.exp) revert InvalidState();
        IdentityRecord storage issuer = activeIdentity(input.issuer);
        if (msg.sender != issuer.identity.managementIdentity) revert Unauthorized();
        activeIdentity(input.grantee);
        CredentialRecord storage issuerVC = validCredential(input.issuerCredentialId, input.issuer, input.issuerKeyVersion);
        CredentialRecord storage granteeVC = validCredential(input.granteeCredentialId, input.grantee, input.granteeKeyVersion);
        if (input.grantId == bytes32(0) || !same(input.schemaVersion, schemaVersion) || input.deploymentId != deploymentId() || input.digest == bytes32(0) ||
            !same(input.authorizationMode, t.task.authorizationMode) || !same(input.principalDomain, t.task.principalDomain) || input.resourceId != t.task.resourceId ||
            input.remainingDepth > 32) revert InvalidStructure();
        checkInterval(input.nbf, input.exp);
        if (input.nbf < t.task.nbf || input.exp > t.task.exp || input.nbf < issuerVC.credential.nbf || input.exp > issuerVC.credential.exp ||
            input.nbf < granteeVC.credential.nbf || input.exp > granteeVC.credential.exp) revert InvalidStructure();
        if (input.parentId == bytes32(0)) {
            if (input.parentDigest != bytes32(0) || input.rootId != input.grantId || input.issuer != resourceOwner ||
                input.grantee != t.task.creator) revert InvalidStructure();
        } else {
            GrantRecord storage parent = grants[input.parentId];
            checkPath(input.parentId);
            if (input.issuer != parent.grant.grantee || input.issuerKeyVersion != parent.grant.granteeKeyVersion ||
                input.issuerCredentialId != parent.grant.granteeCredentialId) revert Unauthorized();
            if (input.parentDigest != parent.grant.digest || input.rootId != parent.grant.rootId || input.taskId != parent.grant.taskId ||
                !same(input.authorizationMode, parent.grant.authorizationMode) || !same(input.principalDomain, parent.grant.principalDomain) ||
                input.resourceId != parent.grant.resourceId || input.nbf < parent.grant.nbf || input.exp > parent.grant.exp ||
                parent.grant.remainingDepth == 0 || input.remainingDepth >= parent.grant.remainingDepth) revert InvalidStructure();
        }
        grants[key] = GrantRecord(input, ACTIVE, 1);
    }

    function getTask(bytes32 id) external view returns (TaskRecord memory) {
        if (tasks[id].status == 0) revert MissingDependency();
        return tasks[id];
    }

    function getGrant(bytes32 id) external view returns (GrantRecord memory) {
        if (grants[id].status == 0) revert MissingDependency();
        return grants[id];
    }

    function revokeGrant(bytes32 id, uint64 expectedRevision, bytes32 expectedDigest) external {
        GrantRecord storage g = grants[id];
        if (g.status == 0) revert MissingDependency();
        bytes32 rootIssuer = grants[g.grant.rootId].grant.issuer;
        if (msg.sender != identities[g.grant.issuer].identity.managementIdentity &&
            msg.sender != identities[g.grant.grantee].identity.managementIdentity &&
            msg.sender != identities[rootIssuer].identity.managementIdentity &&
            msg.sender != identities[resourceOwner].identity.managementIdentity) revert Unauthorized();
        if (g.revision != expectedRevision || g.grant.digest != expectedDigest) revert StateChanged();
        if (g.status != ACTIVE) revert InvalidState();
        g.status = REVOKED;
        ++g.revision;
    }

    function activeIdentity(bytes32 id) private view returns (IdentityRecord storage i) {
        i = identities[id];
        if (i.status == 0) revert MissingDependency();
        if (i.status != ACTIVE) revert InvalidState();
        activeDomain(i.identity.domainId);
    }

    function validCredential(bytes32 id, bytes32 subject, uint64 version) private view returns (CredentialRecord storage c) {
        c = credentials[id];
        if (c.status == 0) revert MissingDependency();
        if (c.status != ACTIVE || c.credential.nbf > block.timestamp || block.timestamp >= c.credential.exp) revert InvalidState();
        IdentityRecord storage holder = activeIdentity(subject);
        IdentityRecord storage issuer = activeIdentity(idHash(c.credential.issuer));
        if (idHash(c.credential.subject) != subject || holder.identity.appKeyVersion != version || c.credential.appKeyVersion != version ||
            issuer.identity.kind != 2 || c.credential.issuerKeyVersion != issuer.identity.appKeyVersion ||
            !same(holder.identity.domainId, issuer.identity.domainId)) revert InvalidStructure();
        DomainRecord storage d = activeDomain(holder.identity.domainId);
        requireIssuerScope(d, c.credential.issuer, c.credential.issuerKeyVersion, c.credential.credentialType);
    }

    function checkPath(bytes32 grantId) private view {
        for (uint256 i; i <= 32; ++i) {
            GrantRecord storage g = grants[grantId];
            if (g.status == 0) revert MissingDependency();
            if (g.status != ACTIVE || g.grant.nbf > block.timestamp || block.timestamp >= g.grant.exp) revert InvalidState();
            validCredential(g.grant.issuerCredentialId, g.grant.issuer, g.grant.issuerKeyVersion);
            validCredential(g.grant.granteeCredentialId, g.grant.grantee, g.grant.granteeKeyVersion);
            if (g.grant.parentId == bytes32(0)) return;
            grantId = g.grant.parentId;
        }
        revert InvalidStructure();
    }

    function requireIssuerScope(DomainRecord storage d, string memory issuer, uint64 version, string memory credentialType) private view {
        DomainCertificationRecord storage c = certifications[d.currentCertificationId];
        for (uint256 i; i < c.certification.identityIssuers.length; ++i) {
            IssuerScope storage scope = c.certification.identityIssuers[i];
            if (same(scope.id, issuer) && scope.appKeyVersion == version) {
                for (uint256 j; j < scope.credentialTypes.length; ++j) {
                    if (same(scope.credentialTypes[j], credentialType)) return;
                }
            }
        }
        revert InvalidStructure();
    }

    function storeIdentity(IdentityInput calldata input, address registrar) private {
        bytes32 key = idHash(input.subjectId);
        if (key == idHash(fixedRoot.rootDid) || identities[key].status != 0 || managementSubjects[input.managementIdentity] != bytes32(0)) revert IdAlreadyUsed();
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
