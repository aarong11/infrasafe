// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";

/**
 * @title InfraSafe
 * @dev Modern Safe-like multisig wallet with upgradeable architecture
 * 
 * Features:
 * - Multisig execution with configurable threshold
 * - Role-based access control for signers and admins
 * - Nonce-based replay protection
 * - ERC-1271 signature validation support
 * - Upgradeable using UUPS pattern
 * - Reentrancy protection
 * - Safe token interactions
 * - Event logging for transparency
 * 
 * Roles:
 * - SAFE_SIGNER_ROLE: Can co-sign transactions
 * - DEFAULT_ADMIN_ROLE: Can manage signers and threshold
 * - TRUSTED_AGENT_ROLE: For AI agent execution (optional enhancement)
 */
contract InfraSafe is 
    Initializable, 
    UUPSUpgradeable, 
    AccessControlEnumerableUpgradeable, 
    ReentrancyGuardUpgradeable,
    IERC1271 
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using SafeERC20 for IERC20;

    // Role definitions
    bytes32 public constant SAFE_SIGNER_ROLE = keccak256("SAFE_SIGNER_ROLE");
    bytes32 public constant TRUSTED_AGENT_ROLE = keccak256("TRUSTED_AGENT_ROLE");

    // ERC-1271 magic value
    bytes4 private constant MAGICVALUE = 0x1626ba7e;

    // State variables
    uint256 public threshold;
    uint256 public nonce;
    address public fallbackHandler;

    // Events
    event TransactionExecuted(
        address indexed to,
        uint256 value,
        bytes data,
        uint256 nonce,
        bytes32 txHash
    );
    
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);
    event FallbackHandlerChanged(address indexed oldHandler, address indexed newHandler);

    // Custom errors
    error InvalidThreshold();
    error InvalidSignatureCount();
    error InvalidSignature();
    error TransactionFailed();
    error Unauthorized();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the InfraSafe contract
     * @param _signers Initial signers array
     * @param _threshold Required signature threshold
     * @param _admin Admin address
     */
    function initialize(
        address[] memory _signers,
        uint256 _threshold,
        address _admin
    ) public initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();

        if (_threshold == 0 || _threshold > _signers.length) {
            revert InvalidThreshold();
        }

        // Grant admin role
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        // Add signers
        for (uint256 i = 0; i < _signers.length; i++) {
            _grantRole(SAFE_SIGNER_ROLE, _signers[i]);
            emit SignerAdded(_signers[i]);
        }

        threshold = _threshold;
        emit ThresholdChanged(0, _threshold);
    }

    /**
     * @dev Executes a transaction with required signatures
     * @param to Target contract address
     * @param value ETH value to send
     * @param data Transaction data
     * @param signatures Array of signatures from signers
     */
    function executeTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        bytes[] calldata signatures
    ) external nonReentrant returns (bool success) {
        if (signatures.length < threshold) {
            revert InvalidSignatureCount();
        }

        bytes32 txHash = getTransactionHash(to, value, data, nonce);
        
        // Verify signatures
        _verifySignatures(txHash, signatures);

        // Increment nonce to prevent replay attacks
        nonce++;

        // Execute transaction
        (success, ) = to.call{value: value}(data);
        if (!success) {
            revert TransactionFailed();
        }

        emit TransactionExecuted(to, value, data, nonce - 1, txHash);
    }

    /**
     * @dev Verifies that signatures meet the threshold requirement
     * @param txHash Hash of the transaction
     * @param signatures Array of signatures to verify
     */
    function _verifySignatures(
        bytes32 txHash,
        bytes[] calldata signatures
    ) internal view {
        address[] memory signers = new address[](signatures.length);
        uint256 validSignatures = 0;

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = txHash.recover(signatures[i]);
            
            // Check if signer has SAFE_SIGNER_ROLE
            if (!hasRole(SAFE_SIGNER_ROLE, signer)) {
                continue;
            }

            // Prevent duplicate signers
            bool isDuplicate = false;
            for (uint256 j = 0; j < validSignatures; j++) {
                if (signers[j] == signer) {
                    isDuplicate = true;
                    break;
                }
            }

            if (!isDuplicate) {
                signers[validSignatures] = signer;
                validSignatures++;
            }
        }

        if (validSignatures < threshold) {
            revert InvalidSignature();
        }
    }

    /**
     * @dev Generates hash for transaction
     * @param to Target address
     * @param value ETH value
     * @param data Transaction data
     * @param _nonce Transaction nonce
     */
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 _nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes1(0x19),
                bytes1(0x01),
                block.chainid,
                address(this),
                to,
                value,
                keccak256(data),
                _nonce
            )
        );
    }

    /**
     * @dev ERC-1271 signature validation
     * @param hash Hash of the data
     * @param signature Signature to validate
     */
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view override returns (bytes4) {
        address signer = hash.recover(signature);
        
        if (hasRole(SAFE_SIGNER_ROLE, signer)) {
            return MAGICVALUE;
        }
        
        return 0xffffffff;
    }

    /**
     * @dev Add a new signer
     * @param signer Address to add as signer
     */
    function addSigner(address signer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(SAFE_SIGNER_ROLE, signer);
        emit SignerAdded(signer);
    }

    /**
     * @dev Remove a signer
     * @param signer Address to remove from signers
     */
    function removeSigner(address signer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(SAFE_SIGNER_ROLE, signer);
        
        // Ensure threshold is still valid after removing signer
        uint256 signerCount = getRoleMemberCount(SAFE_SIGNER_ROLE);
        if (threshold > signerCount && signerCount > 0) {
            threshold = signerCount;
            emit ThresholdChanged(threshold, signerCount);
        }
        
        emit SignerRemoved(signer);
    }

    /**
     * @dev Change signature threshold
     * @param _threshold New threshold value
     */
    function changeThreshold(uint256 _threshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 signerCount = getRoleMemberCount(SAFE_SIGNER_ROLE);
        
        if (_threshold == 0 || _threshold > signerCount) {
            revert InvalidThreshold();
        }
        
        uint256 oldThreshold = threshold;
        threshold = _threshold;
        emit ThresholdChanged(oldThreshold, _threshold);
    }

    /**
     * @dev Set fallback handler for delegated calls
     * @param handler Address of the fallback handler
     */
    function setFallbackHandler(address handler) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address oldHandler = fallbackHandler;
        fallbackHandler = handler;
        emit FallbackHandlerChanged(oldHandler, handler);
    }

    /**
     * @dev Get current signer count
     */
    function getSignerCount() external view returns (uint256) {
        return getRoleMemberCount(SAFE_SIGNER_ROLE);
    }

    /**
     * @dev Get signer at index
     * @param index Index of the signer
     */
    function getSignerAtIndex(uint256 index) external view returns (address) {
        return getRoleMember(SAFE_SIGNER_ROLE, index);
    }

    /**
     * @dev Check if address is a signer
     * @param account Address to check
     */
    function isSigner(address account) external view returns (bool) {
        return hasRole(SAFE_SIGNER_ROLE, account);
    }

    /**
     * @dev Fallback function for delegated calls
     */
    fallback() external payable {
        if (fallbackHandler != address(0)) {
            assembly {
                calldatacopy(0, 0, calldatasize())
                let result := delegatecall(gas(), sload(fallbackHandler.slot), 0, calldatasize(), 0, 0)
                returndatacopy(0, 0, returndatasize())
                switch result
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
            }
        }
    }

    /**
     * @dev Receive function to accept ETH
     */
    receive() external payable {}

    /**
     * @dev Emergency token recovery (admin only)
     * @param token Token contract address
     * @param to Recipient address
     * @param amount Amount to recover
     */
    function emergencyTokenRecovery(
        IERC20 token,
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        token.safeTransfer(to, amount);
    }

    /**
     * @dev Required by UUPSUpgradeable
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /**
     * @dev Get contract version for upgrades
     */
    function version() external pure returns (string memory) {
        return "1.0.0";
    }
}
