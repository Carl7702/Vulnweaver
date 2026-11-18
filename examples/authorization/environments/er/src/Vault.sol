// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

contract Vault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Root-cause neutralization: unauthorized calls have no effect.
    function setOwner(address nextOwner) external {
        if (msg.sender != owner) return;
        owner = nextOwner;
    }
}

