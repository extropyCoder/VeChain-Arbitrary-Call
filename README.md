# Bug Description
Executor.execute() performs an unchecked, low-level external call using proposals[_proposalID].target and proposals[_proposalID].data. Because there is no validation of the target address or the calldata, a proposal that meets the (lightweight) on-chain preconditions can cause the Executor to call any external contract with any calldata. This enables a governance adversary who can shepherd a proposal to quorum to cause arbitrary external side effects — including calls that transfer funds, change state in other contracts, or otherwise escalate into full system compromise.
# Brief/Intro
The executor contract lets a successful proposal execute arbitrary low-level calls to any address using unvalidated calldata. If an attacker can get a proposal to pass quorum, they can force the executor to call arbitrary contracts and functions — potentially draining funds, changing critical state, or taking over system components. A benign local PoC demonstrates the problem by calling a harmless contract function.
# Details
The root cause is this raw call in execute():
```
// executor.sol (excerpt)
proposals[_proposalID].executed = true; // set before call to prevent re-enter attack
require(proposals[_proposalID].target.call(proposals[_proposalID].data), "builtin: proposal execution reverted");
```

Problems:

Unvalidated target — target may be any address at the time of execution; no whitelist or ability check.

Unvalidated calldata — data is used directly; no selector, argument, or ABI checking.

Powerful preconditions — the only checks are presence of the proposal, that it’s not expired/executed, and approvalCount >= quorum. If an attacker can reach quorum (or collude with approvers), they get an execute() that will call arbitrary code.

Low-level call — call(...) forwards no type information and permits any function selector; it can trigger token transfers, self-destructs, delegatecalls, or other sensitive functions on target contracts that lack their own caller checks.

Because these two values (target and data) are controlled by the proposal creator / the proposal entry, the executor effectively becomes an oracle that will execute arbitrary external code once governance approval is reached.

# Impact
Potential impacts depend on what the Executor is permitted to call and which other contracts exist in the system. Examples of realistic and in-scope impacts:

Loss of funds: If an attacker crafts calldata to call token transfer functions on token contracts (or to call a contract that has privileged transfer functions callable by the executor), they could move tokens out of protocol or treasury accounts.

Asset custody compromise: If the executor can call into vaults or multisigs that mistakenly allow such calls, attacker can drain or lock assets.

Governance or ownership takeover: The executor could call owner-only functions on other contracts (for example, transferOwnership()), or call into a timelock that can schedule privileged operations.

Denial-of-service / protocol disruption: Calls could change pausing flags, upgrade logic, or otherwise put important modules into a broken state.

Chained/exploitative actions: Using a sequence of calls an attacker can escalate from a single arbitrary call to full system compromise.

Severity: High → Critical in most realistic deployments where the Executor is intended to execute governance-approved changes and has access to critical system components or treasury funds.

Note: the supplied PoC is benign and flips a boolean only; it demonstrates feasibility without any fund movement.
# Risk Breakdown
Assessing exploitability:

Prerequisites: ability to create a proposal and get it to quorum (approvalCount ≥ quorum). On many deployments this requires control of some voting power or collusion with approvers. If approvals are trivial to obtain (few approvers, automated approvals, or weak processes), exploitability is high.

Exploit complexity: low — once quorum is obtained, execute() requires a single transaction with stored target and data. Crafting calldata is straightforward (standard ABI encoding).

Detectability: medium — execution emits the contract’s events, but the call itself can be disguised as governance action. If monitoring is lax, detection may be late.

Speed / blast radius: high — a single execution can be used to transfer large funds or change ownership quickly.

Likelihood: depends on governance hygiene. If multisigs / timelocks / large quorum thresholds exist, exploitation is harder; if quorum is small or approvals can be automated, it’s easy.

Using the Immunefi classification, this fits High / Critical for systems where Executor can reach privileged or treasury-bearing contracts.
# Recommendation
Immediate/short-term mitigations :

1. Remove raw, arbitrary .call usage
Replace require(target.call(data)) with controlled forwarding functions that only allow specific, audited interactions.

2. Whitelist approved targets
Maintain a whitelist of target addresses that the executor may call. Reject proposals whose target is not on the whitelist.

3. Whitelist function selectors  
For each whitelisted target, restrict which function selectors may be called (e.g. allow only updateParameter(bytes32,uint256) selectors). Reject calldata that does not match allowed selectors.

4. Add stronger governance gating

- Require a timelock (delay) between approval and execution for sensitive operations.

- Require multi-sig confirmation for proposals that touch treasury or admin functions.

- Increase quorum / approval thresholds for privileged actions.

5. Validate calldata
If dynamic approval is required, implement ABI validation/decoding server-side or on-chain checks to ensure only safe function calls are forwarded.

6. Reduce executor privileges
Ensure downstream contracts enforce role-based access control so an arbitrary call from Executor cannot unilaterally transfer funds (i.e. sensitive functions should verify msg.sender is an expected contract or multi-sig).

7. Add logging & alerting
Emit detailed events (target, selector, proposer, timestamp) on execute() and alert on calls to previously unseen targets/selectors.

Suggested  whitelist check:
```solidity
mapping(address => bool) public allowedTargets;
mapping(address => mapping(bytes4 => bool)) public allowedSelectors; // optional

function execute(bytes32 _proposalID) public {
    // ... existing prechecks ...

    address target = proposals[_proposalID].target;
    bytes4 selector = bytes4(proposals[_proposalID].data[:4]);

    require(allowedTargets[target], "executor: target not allowed");
    require(allowedSelectors[target][selector], "executor: selector not allowed");

    proposals[_proposalID].executed = true;
    (bool ok, ) = target.call(proposals[_proposalID].data);
    require(ok, "executor: proposal execution reverted");
}

```



# References
Files used in PoC:

src/external/executor.sol — vulnerable Executor contract (exact file provided).

src/mocks/PoCReceiver.sol — benign target used by PoC (flips boolean + emits event).

test/Executor_ArbitraryCall_PoC.t.sol — Foundry test that demonstrates the issue (safe, local).


# Proof of Concept
How to run the PoC (local, safe - using a safe target):

Ensure foundry.toml includes:

[profile.default]
auto_detect_solc = true
evm_version = "constantinople"


Run:

forge clean
forge build
forge test -vv --match-path test/Executor_ArbitraryCall_PoC.t.sol
