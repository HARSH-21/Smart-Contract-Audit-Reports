# Ethereal Smart Contract — Combined Security Audit Report
 
**Contract:** Ethereal.sol  
**Standard:** ERC721 (NFT)  
**Language:** Solidity ^0.8.0  
**Dependencies:** OpenZeppelin (Ownable, Pausable, ERC721URIStorage, ERC721Holder, ReentrancyGuard)  


## Audit Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 5 |
| Medium | 6 |
| Low | 5 |
| Informational / Gas | 3 |
| **Total** | **21** |


## Findings

---

### [C-01] Reentrancy in `_redeemEth` via `safeTransferFrom`

**Severity:** Critical  
**Location:** `_redeemEth()`

**Description:**

The function calls `safeTransferFrom` as its very first operation, before any state has been updated. `safeTransferFrom` triggers `onERC721Received` on the recipient — which in this case is `address(this)`, the contract itself. Because the contract overrides `onERC721Received`, a malicious caller can hook into that callback while `metadata[_tokenId].balance` is still non-zero and exploit the stale state.

The `nonReentrant` guard exists on `redeem()`, but it does not protect here because the reentrant path runs within the same call stack, through the `safeTransferFrom` callback, before the guard's lock is checked again.

```solidity
// Vulnerable ordering
function _redeemEth(uint256 _tokenId) internal {
    safeTransferFrom(msg.sender, address(this), _tokenId); // external call triggers onERC721Received
    _burn(_tokenId);
    circulatingGems--;
    uint256 redeemFee = (metadata[_tokenId].balance * gems[metadata[_tokenId].gem].redeemFee) / 1e4;
    uint256 amount = metadata[_tokenId].balance - redeemFee;
    fees += redeemFee;
    metadata[_tokenId].balance = 0;  // zeroed too late
    (bool success,) = msg.sender.call{value: amount}(" ");
    require(success, " ");
    emit GemRedeemed(_tokenId, msg.sender, amount);
}
```

**Recommended Fix — strict Checks-Effects-Interactions ordering:**

```solidity
function _redeemEth(uint256 _tokenId) internal {
    // Effects first
    uint256 balance = metadata[_tokenId].balance;
    metadata[_tokenId].balance = 0;
    circulatingGems--;
    uint256 redeemFee = (balance * gems[metadata[_tokenId].gem].redeemFee) / 1e4;
    uint256 amount = balance - redeemFee;
    fees += redeemFee;
    _burn(_tokenId);

    // Interactions last
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "ETH transfer failed");
    emit GemRedeemed(_tokenId, msg.sender, amount);
}
```

---

### [C-02] CEI Violation in `_redeemWstEth`

**Severity:** Critical  
**Location:** `_redeemWstEth()`

**Description:**

The same pattern appears in the wstETH redemption path. `safeTransferFrom` is called before state is updated, leaving `metadata[_tokenId].balance` non-zero during the external call. Additionally, the wstETH transfer — another external call — happens last, after state has been partially updated. A compromised or maliciously upgraded `wstETH` contract address could exploit the window between these two external calls.

```solidity
// Vulnerable ordering
function _redeemWstEth(uint256 _tokenId) internal {
    safeTransferFrom(msg.sender, address(this), _tokenId); // external call — state not yet updated
    uint256 redeemFee = metadata[_tokenId].balance * gems[metadata[_tokenId].gem].redeemFee / 1e4;
    uint256 amount = metadata[_tokenId].balance - redeemFee;
    fees += redeemFee;
    metadata[_tokenId].balance = 0;
    _burn(_tokenId);
    circulatingGems--;
    IwstETH(wstETH).transfer(msg.sender, amount); // external call — see H-04 for unchecked return value
    emit GemRedeemed(_tokenId, msg.sender, amount);
}
```

**Recommended Fix:**

```solidity
function _redeemWstEth(uint256 _tokenId) internal {
    uint256 balance = metadata[_tokenId].balance;
    metadata[_tokenId].balance = 0;
    circulatingGems--;
    uint256 redeemFee = (balance * gems[metadata[_tokenId].gem].redeemFee) / 1e4;
    uint256 amount = balance - redeemFee;
    fees += redeemFee;
    _burn(_tokenId);

    bool success = IwstETH(wstETH).transfer(msg.sender, amount);
    require(success, "wstETH transfer failed");
    emit GemRedeemed(_tokenId, msg.sender, amount);
}
```

---

### [H-01] Unsafe Low-Level Call for wstETH Deposit

**Severity:** High  
**Location:** `_mintWstEth()`

**Description:**

The function deposits ETH into the wstETH contract using a raw low-level call rather than a typed interface function. This assumes the wstETH contract accepts ETH via its fallback or receive function, but there is no validation that the target exists or handles the call correctly. If the `wstETH` address is changed (via `setWstEth`) to a contract that does not accept ETH, the low-level call may succeed while doing nothing — leaving the balance delta at zero and minting an NFT with an empty balance that can never be redeemed for any value.

```solidity
// Problematic pattern
(bool success,) = wstETH.call{value: msg.value}("");
require(success, "Failed to deposit Ether");
// If target accepts ETH but doesn't issue wstETH, preBalance == postBalance
metadata[tokenId_] = Metadata(IwstETH(wstETH).balanceOf(address(this)) - preBalance, _collection, _id);
```

**Recommended Fix:**

```solidity
require(wstETH.code.length > 0, "wstETH contract does not exist");
IwstETH(wstETH).deposit{value: msg.value}();
uint256 postBalance = IwstETH(wstETH).balanceOf(address(this));
require(postBalance > preBalance, "Deposit failed or returned nothing");
metadata[tokenId_] = Metadata(postBalance - preBalance, _collection, _id);
```

---

### [H-02] Uncapped Redemption Fee Allows Full Fund Extraction

**Severity:** High  
**Location:** `createGem()`, `updateGem()`

**Description:**

Neither function validates the `_redeemFee` parameter. The fee system uses a basis-point scale where 10,000 equals 100%, but there is no upper bound check. An owner can set the fee to 10,000 or higher, meaning a user who mints a gem deposits ETH and receives zero back on redemption — the entire deposit flows to the protocol as a fee.

```solidity
// No validation on redeemFee
function createGem(uint256 _collection, uint256 _denomination, uint256 _redeemFee, bool _active)
    external onlyOwner returns (uint256 id_)
{
    gems.push(Gem({..., redeemFee: _redeemFee, ...})); // _redeemFee can be 10000+ 
}
```

**Recommended Fix:**

```solidity
require(_redeemFee <= 1000, "Redemption fee cannot exceed 10%");
```

Apply the same check in `updateGem()`.

---

### [H-03] `updateGem` Can Retroactively Modify Live Circulating Gems

**Severity:** High  
**Location:** `updateGem()`

**Description:**

The owner can change `redeemFee` and `denomination` for any gem type at any time, including after tokens have been minted and are circulating. A user who minted expecting a 1% fee could find it changed to 10% before they redeem. This creates an economic trust risk that is structurally equivalent to a rug vector — the contract offers no guarantee of the redemption terms users originally accepted.

**Recommended Fix:**

Track a per-gem `circulatingSupply` counter and disallow changes to `redeemFee` while any tokens of that gem type are outstanding. Alternatively, snapshot the fee into `Metadata` at mint time so each token carries its own immutable fee record.

---

### [H-04] Unchecked Return Value on wstETH Transfer

**Severity:** High  
**Location:** `_redeemWstEth()`

**Description:**

`IwstETH(wstETH).transfer(msg.sender, amount)` is called without checking the return value. ERC20 tokens are not required to revert on failure — many return `false` instead. If the transfer silently fails (for example, if the wstETH contract is paused, the user is blacklisted, or a balance shortfall exists), the NFT will have already been burned and the user receives nothing. The contract state will show the redemption as complete while the user loses both the token and the underlying asset.

**Recommended Fix:**

```solidity
bool success = IwstETH(wstETH).transfer(msg.sender, amount);
require(success, "wstETH transfer failed");
```

Or, preferably, use OpenZeppelin's `SafeERC20.safeTransfer()` which handles non-reverting ERC20s consistently.

---

### [H-05] `approveWstEth` Grants Unlimited Allowance to Any Address

**Severity:** High  
**Location:** `approveWstEth()`

**Description:**

This function grants `type(uint256).max` approval of the contract's wstETH holdings to any address specified by the owner. There is no cap, no revocation path, and no timelocked protection. If the owner's private key is compromised, an attacker can immediately drain all wstETH held by the contract by directing an approval to a malicious spender.

```solidity
function approveWstEth(address _spender) external onlyOwner {
    IwstETH(wstETH).approve(_spender, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
}
```

**Recommended Fix:**

Remove this function entirely if not strictly required. If it is needed for protocol integrations, restrict it to approve only the exact amount required at that moment, and gate it behind a multisig or timelock.

---

### [M-01] ETH and wstETH Fees Share a Single Counter — wstETH Fees Are Permanently Locked

**Severity:** Medium  
**Location:** `fees` state variable, `withdrawFees()`

**Description:**

Both ETH fees and wstETH fees are accumulated into the same `fees` variable. However, `withdrawFees()` only withdraws ETH via `payout.call{value: fees}`. Any fees accrued from wstETH redemptions are added to `fees` as a numeric amount but can never be retrieved — they are stuck in the contract indefinitely with no withdrawal path.

```solidity
// Both fee types share one counter
uint256 public fees = 0;

// Only withdraws ETH — wstETH fees remain stuck
function withdrawFees() external onlyOwner {
    (bool success,) = payout.call{value: fees}("");
    require(success, "Transfer failed");
    fees = 0;
}
```

**Recommended Fix:**

```solidity
uint256 public ethFees;
uint256 public wstEthFees;

function withdrawEthFees() external onlyOwner {
    uint256 amount = ethFees;
    ethFees = 0;
    (bool success,) = payout.call{value: amount}("");
    require(success, "Transfer failed");
}

function withdrawWstEthFees() external onlyOwner {
    uint256 amount = wstEthFees;
    wstEthFees = 0;
    IwstETH(wstETH).transfer(payout, amount);
}
```

---

### [M-02] `onERC721Received` Accepts Any ERC721 Token

**Severity:** Medium  
**Location:** `onERC721Received()`

**Description:**

The contract unconditionally accepts any ERC721 token sent to it, not just its own. This means arbitrary NFTs transferred to this address will be permanently locked with no recovery mechanism. The override also computes the selector via `keccak256` rather than using the more idiomatic `this.onERC721Received.selector`.

```solidity
// Accepts all ERC721 tokens unconditionally
function onERC721Received(address, address, uint256, bytes memory) public virtual override returns (bytes4) {
    return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
}
```

**Recommended Fix:**

```solidity
function onERC721Received(address, address, uint256, bytes memory) public virtual override returns (bytes4) {
    require(msg.sender == address(this), "Only own tokens accepted");
    return this.onERC721Received.selector;
}
```

---

### [M-03] `whenNotPaused` Missing from `redeem()`

**Severity:** Medium  
**Location:** `redeem()`

**Description:**

`mint()` is correctly gated by `whenNotPaused`, but `redeem()` has no pause protection. During a security incident requiring an emergency pause, token holders can continue redeeming — potentially draining the contract while the vulnerability window is open. If this is an intentional design decision (users should always be able to exit), it must be explicitly documented in the contract and communicated to users.

---

### [M-04] Centralization Risk — `setWstEth` Has No Timelock or Governance Control

**Severity:** Medium  
**Location:** `setWstEth()`

**Description:**

The owner can change the `wstETH` address at any time without delay. Swapping this address to a malicious contract would affect all future mints and redemptions. Combined with the low-level call pattern in `_mintWstEth` (see H-01), an owner-controlled address change is a realistic attack vector — either through key compromise or an insider action. There is no timelock, no multisig requirement, and no event emitted when the change occurs (see I-01).

**Recommended Fix:**

Gate `setWstEth` behind a timelock with a meaningful delay (e.g., 48 hours), giving users time to observe and react to the change before it takes effect.

---

### [M-05] Unbounded Array Access — Panic Revert Risk

**Severity:** Medium  
**Location:** `mint()`, `updateCollection()`, `updateGem()`, `ceaseGem()`, `tokenURI()`, `redeem()`

**Description:**

No bounds checks exist on `gems[_id]`, `collections[_id]`, or `metadata[_tokenId]` before access. An out-of-bounds index causes an unhelpful panic revert. More critically, `mint()` accepts `_id` directly from user input with no validation — passing an invalid gem ID triggers a panic rather than a descriptive error message, which makes integrations difficult to reason about.

**Recommended Fix:**

```solidity
require(_id < gems.length, "Gem does not exist");
require(gems[_id].collection < collections.length, "Invalid collection");
```

---

### [M-06] Balance-Diff Pattern in `_mintWstEth` Is Manipulation-Prone

**Severity:** Medium  
**Location:** `_mintWstEth()`

**Description:**

The contract uses a pre/post balance difference to determine how much wstETH was received from the deposit. This is generally a sound approach, but two issues weaken it here. First, `_safeMint` is called before the balance snapshot, meaning a reentrant callback during `_safeMint` could corrupt `preBalance`. Second, a direct wstETH donation to the contract address in the same block (before the post-balance check) inflates the minted gem's recorded balance, allowing the donor to profit on a future redemption or to grief the protocol accounting.

**Recommended Fix:**

Move `_safeMint` after the balance accounting is complete. Consider tracking expected deposits in a dedicated state variable rather than relying on live balance diffs.

---

### [L-01] Missing Zero Address Validation in Constructor

**Severity:** Low  
**Location:** `constructor()`

**Description:**

The constructor sets `payout = msg.sender` without validating that the deployer is not the zero address. In edge cases involving factory deployments or proxies, `msg.sender` could theoretically be zero, making `withdrawFees()` send ETH to `address(0)` — where it is lost forever.

**Recommended Fix:**

```solidity
constructor() ERC721("Ethereal", "ETHRL") Ownable(msg.sender) {
    require(msg.sender != address(0), "Deployer cannot be zero address");
    payout = msg.sender;
}
```

---

### [L-02] Empty String and Useless Error Messages in `_redeemEth`

**Severity:** Low  
**Location:** `_redeemEth()`

**Description:**

Two issues in the same function: a space character `" "` is passed as call data to the ETH send instead of an empty string `""`, and the revert message on failure is also just a space `" "`. Neither causes a vulnerability, but both indicate incomplete code and make debugging harder.

**Recommended Fix:**

```solidity
(bool success,) = msg.sender.call{value: amount}("");
require(success, "ETH transfer failed");
```

---

### [L-03] `msg.value` Recorded Directly in `_mintEth` Is Fragile

**Severity:** Low  
**Location:** `_mintEth()`

**Description:**

`metadata[tokenId_] = Metadata(msg.value, ...)` works correctly today because of the strict denomination equality check, but it couples balance recording tightly to `msg.value`. If the denomination check were ever loosened (for example, to allow `>= denomination`), this could record values that are inconsistent with the protocol's internal accounting.

**Recommended Fix:**

Record the gem's denomination value rather than `msg.value`, or add a defensive assertion confirming they are equal before recording.

---

### [L-04] Overly Broad Compiler Pragma

**Severity:** Low  
**Location:** Top of file

**Description:**

`pragma solidity ^0.8.0` permits compilation with any 0.8.x compiler version, including future ones that may introduce breaking changes or new edge cases. Pinning to a specific version ensures consistent, reproducible builds.

**Recommended Fix:**

```solidity
pragma solidity 0.8.24;
```

---

### [L-05] Redundant `circulatingGems` Getter

**Severity:** Low  
**Location:** State variable and `gemsCirculating()`

**Description:**

`circulatingGems` is declared `internal` but has a public getter function `gemsCirculating()`. Declaring the variable `public` directly achieves the same result with less code.

---

### [I-01] Missing Events on Critical Admin State Changes

**Severity:** Informational  
**Location:** `updateCollection()`, `updateGem()`, `setWstEth()`, `setPayout()`, `approveWstEth()`

**Description:**

None of these functions emit events. Changes to the `wstETH` address, payout address, fee rates, and gem configurations are material protocol events that off-chain monitors, users, and integrations need to observe. Unlimited approvals granted via `approveWstEth` are particularly important to log.

**Recommended Fix:**

Add dedicated events for each admin action and emit them in every relevant function.

---

### [I-02] `IwstETH.balanceOf` Not Marked `view`

**Severity:** Informational  
**Location:** `IwstETH` interface

**Description:**

The `balanceOf` function in the `IwstETH` interface is missing the `view` modifier. While the actual wstETH contract implementation is view-safe, the mismatch between the interface and the real ABI can cause unexpected behavior in static analysis tools and off-chain call simulations.

**Recommended Fix:**

```solidity
function balanceOf(address account) external view returns (uint256);
```

---

### [I-03] Legacy `toString()` Utility Should Use OpenZeppelin

**Severity:** Informational  
**Location:** `toString()` utility function

**Description:**

The contract contains a manual `toString()` implementation copied from legacy OraclizeAPI code. OpenZeppelin already provides a well-tested `Strings.toString()` that is already within the dependency tree.

**Recommended Fix:**

Remove the manual implementation and import `Strings` from OpenZeppelin.
