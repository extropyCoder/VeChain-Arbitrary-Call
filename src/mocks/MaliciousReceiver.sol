// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Harmless logger used to illustrate how an attacker could craft calldata
/// that *looks* like a drain. This contract only records parameters and emits an event.
contract MaliciousReceiver {
    address public lastToken;
    address public lastTo;
    uint256 public lastAmount;

    event AttemptedTransfer(address token, address to, uint256 amount, address caller);

    function simulateTokenDrain(address token, address to, uint256 amount) external {
        lastToken = token;
        lastTo = to;
        lastAmount = amount;
        emit AttemptedTransfer(token, to, amount, msg.sender);
    }
}
