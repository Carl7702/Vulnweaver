// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

contract Treasury {
    address public owner;
    uint256 public treasuryBalance = 1_000;
    uint256 public attackerBalance;

    constructor(address initialOwner) {
        owner = initialOwner;
    }

    // Vulnerability: no ownership check.
    function drain(uint256 amount) external {
        if (treasuryBalance < amount) return;
        treasuryBalance -= amount;
        attackerBalance += amount;
    }
}

