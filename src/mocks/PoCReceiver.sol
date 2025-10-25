// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract PoCReceiver {
    bool public called;
    event Called(address indexed caller);

    function markCalled() external {
        called = true;
        emit Called(msg.sender);
    }
}
