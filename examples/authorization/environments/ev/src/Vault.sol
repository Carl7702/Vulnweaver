// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

contract Vault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Vulnerability: no caller authorization.
    function setOwner(address nextOwner) external {
        owner = nextOwner;
    }
}

