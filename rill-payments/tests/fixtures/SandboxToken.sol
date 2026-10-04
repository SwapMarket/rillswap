// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Disposable nonproxy fixture, never a production token or funded asset.
contract SandboxToken {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 supply) {
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "zero recipient");
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
