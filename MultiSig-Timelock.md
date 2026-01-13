# MultiSig Timelock - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)

- ## Medium Risk Findings
    - ### [M-01. Role Revocation Does Not Invalidate Existing Confirmations](#M-01)
    - ### [M-02. Confirmation Count Can Become Inconsistent With Actual Signatures](#M-02)



# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #55

### Dates: Dec 18th, 2025 - Dec 25th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-12-multisig-timelock)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 0
- Medium: 2
- Low: 0



    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Role Revocation Does Not Invalidate Existing Confirmations            



# Root + Impact

Only addresses with `SIGNING_ROLE` should influence transaction execution.

 

## Description

If a signer:

 

1. Confirms a transaction
2. Later loses `SIGNING_ROLE`

Their confirmation **remains valid forever**, even though they are no longer authorized.

```Solidity
// @> No cleanup of s_signatures when SIGNING_ROLE is revoked
s_signatures[txnId][formerSigner] == true

```

* Describe the normal behavior in one or more sentences

* Explain the specific issue or problem in one or more sentences

```solidity
// Root cause in the codebase with @> marks to highlight the relevant section
```

## Risk

**Likelihood**:

* Occurs when admin removes compromised or malicious signer

*  

  Occurs during signer rotation

**Impact**:

* Revoked signers still influence fund movement

*  

  Breaks role-based security model

## Proof of Concept

```Solidity
// 1. Signer A confirms txn
// 2. Admin revokes SIGNING_ROLE from A
// 3. Transaction still counts A's confirmation

```

## Recommended Mitigation

Or enforce `onlyRole(SIGNING_ROLE)` **at execution-time confirmation validation**.

```diff
+ function revokeRole(...) internal override {
+     _clearSignerConfirmations(account);
+ }

```

## <a id='M-02'></a>M-02. Confirmation Count Can Become Inconsistent With Actual Signatures            



# Root + Impact

## Description

* The contract tracks confirmations using:

   

  * a mapping: `s_signatures[txnId][signer]`
  * a counter: `s_transactions[txnId].confirmations`
  * The counter is expected to **always match** the number of `true` signature entries.

     

    <br />

  - The contract **trusts the counter** during execution (`_executeTransaction`) but **never re-validates it against the signature mapping**. If the counter ever becomes inconsistent (due to future changes, role revocation edge cases, or logic bugs), a transaction may execute with fewer real approvals than intended.

```Solidity
if (txn.confirmations < REQUIRED_CONFIRMATIONS) {
    revert MultiSigTimelock__InsufficientConfirmations(...);
}
```

## Risk

**Likelihood**:

* Occurs when signer roles are revoked after confirmation
* Occurs if future code paths mutate `confirmations` incorrectly

 

**Impact**:

* Transaction executes with fewer than 3 valid signer approvals

*  

  Governance and multisig guarantees weakened

## Proof of Concept

```Solidity
// Scenario (conceptual):
// 1. Signer A, B, C confirm → confirmations = 3
// 2. Admin revokes SIGNING_ROLE from signer C
// 3. confirmations counter still = 3
// 4. executeTransaction() succeeds even though only A & B are valid signers
```

## Recommended Mitigation

Recalculate confirmations dynamically at execution time OR enforce invariant:

 

```diff
+ uint256 actualConfirmations = 0;
+ for (uint256 i = 0; i < signerList.length; i++) {
+     if (s_signatures[txnId][signerList[i]]) {
+         actualConfirmations++;
+     }
+ }
+ require(actualConfirmations >= REQUIRED_CONFIRMATIONS, "Invalid confirmations");

```





