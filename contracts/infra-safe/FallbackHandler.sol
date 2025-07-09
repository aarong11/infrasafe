// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title FallbackHandler
 * @dev Handles fallback delegatecalls for InfraSafe extensions
 * 
 * This contract enables pluggable functionality for InfraSafe without
 * requiring contract upgrades. Extensions can be added for:
 * - Biometric recovery mechanisms
 * - AI agent interactions
 * - Custom transaction validation
 * - Social recovery features
 * 
 * Security considerations:
 * - Only trusted handlers should be registered
 * - Pre/post execution hooks for monitoring
 * - Reentrancy protection on sensitive operations
 */
contract FallbackHandler is Ownable, ReentrancyGuard {
    
    // Mapping from function selector to handler address
    mapping(bytes4 => address) public handlers;
    
    // Events
    event HandlerSet(bytes4 indexed selector, address indexed handler);
    event HandlerRemoved(bytes4 indexed selector);
    event PreExecutionHook(bytes4 indexed selector, address indexed caller, bytes data);
    event PostExecutionHook(bytes4 indexed selector, address indexed caller, bytes data, bool success);

    // Custom errors
    error HandlerNotFound();
    error InvalidHandler();

    constructor(address initialOwner) Ownable(initialOwner) {}

    /**
     * @dev Set handler for a specific function selector
     * @param selector Function selector (first 4 bytes of function signature)
     * @param handler Address of the handler contract
     */
    function setHandler(bytes4 selector, address handler) external onlyOwner {
        if (handler == address(0)) {
            revert InvalidHandler();
        }
        
        handlers[selector] = handler;
        emit HandlerSet(selector, handler);
    }

    /**
     * @dev Remove handler for a function selector
     * @param selector Function selector to remove
     */
    function removeHandler(bytes4 selector) external onlyOwner {
        delete handlers[selector];
        emit HandlerRemoved(selector);
    }

    /**
     * @dev Get handler for a function selector
     * @param selector Function selector
     */
    function getHandler(bytes4 selector) external view returns (address) {
        return handlers[selector];
    }

    /**
     * @dev Fallback function that delegates to appropriate handler
     */
    fallback() external payable nonReentrant {
        bytes4 selector = bytes4(msg.data);
        address handler = handlers[selector];
        
        if (handler == address(0)) {
            revert HandlerNotFound();
        }

        // Pre-execution hook
        emit PreExecutionHook(selector, msg.sender, msg.data);

        // Delegate call to handler
        (bool success, bytes memory result) = handler.delegatecall(msg.data);
        
        // Post-execution hook
        emit PostExecutionHook(selector, msg.sender, msg.data, success);

        if (success) {
            assembly {
                return(add(result, 0x20), mload(result))
            }
        } else {
            assembly {
                revert(add(result, 0x20), mload(result))
            }
        }
    }

    /**
     * @dev Receive function to accept ETH
     */
    receive() external payable {}

    /**
     * @dev Emergency function to recover stuck funds
     * @param to Recipient address
     * @param amount Amount to send
     */
    function emergencyWithdraw(address payable to, uint256 amount) external onlyOwner {
        require(to != address(0), "Invalid recipient");
        require(amount <= address(this).balance, "Insufficient balance");
        
        to.transfer(amount);
    }

    /**
     * @dev Get contract version
     */
    function version() external pure returns (string memory) {
        return "1.0.0";
    }
}
