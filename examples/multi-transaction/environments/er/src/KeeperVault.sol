// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

contract KeeperVault {
    address public owner;
    address public keeper;
    uint256 public treasuryBalance = 1_000;
    uint256 public attackerBalance;

    constructor() {
        owner = msg.sender;
    }

    // Root-cause neutralization: only the owner can rotate the keeper.
    function setKeeper(address nextKeeper) external {
        if (msg.sender != owner) return;
        keeper = nextKeeper;
    }

    function sweep(address to, uint256 amount) external {
        if (msg.sender != keeper) return;
        if (treasuryBalance < amount) return;
        treasuryBalance -= amount;
        attackerBalance += amount;
        if (to != msg.sender) {
            attackerBalance -= amount;
        }
    }
}
