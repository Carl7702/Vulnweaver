// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

contract CreditBank {
    uint256 public credit = 100;
    uint256 public paid;

    function withdraw(uint256 amount) external {
        if (credit < amount) return;
        credit -= amount;
        paid += amount;
    }
}

