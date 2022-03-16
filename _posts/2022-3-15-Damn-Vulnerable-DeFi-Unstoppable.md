---
layout: post
title:  Damn Vulnerable DeFi - Unstoppable
categories: [DeFi, Solidity, DVDF]
excerpt: Writeup for Unstoppable.
---
# Unstoppable

First off, [the pwnable is here](https://www.damnvulnerabledefi.xyz/challenges/1.html). I'll be talking from the perspective of someone with some exploit dev experience (say, completion of [pwncollege](https://pwn.college/)), but with basically no Solidity nor DeFi experience.

[Solidity By Example](https://docs.soliditylang.org/en/v0.8.0/solidity-by-example.html) is pretty good for giving a basic introduction to the language and will be assumed.

Also, skimming through notes on Flash Loans along with a skim through the interface defined by
ERC20 is helpful (the former for context, and the latter for the solution).

## What Do We Have To Accomplish?

The following test has to pass:
```js
await expect(
  this.receiverContract.executeFlashLoan(10)
).to.be.reverted;
```

So, we have to somehow cause an assert or require to pop (in principle
unconditionally) within the `executeFlashLoan` function, regardless
of the argument passed in.

We can clearly see that this points to `flashLoan`, and the following
asserts / requires define our attack surface a little more:

## Defining The Attack Surface

```solidity 
require(borrowAmount > 0, "Must borrow at least one token");
require(balanceBefore >= borrowAmount, "Not enough tokens in pool");
assert(poolBalance == balanceBefore);
require(balanceAfter >= balanceBefore, "Flash loan hasn't been paid back");
```

`borrowAmount` is a passed in argument from the user, and we have to cause a revertion regardless of what happens, which immediately removes `borrowAmount > 0` from our attack surface.

Considering `balanceBefore >= borrowAmount`, we can then redefine our attack surrface to be (more precisely, anyways) `damnValuableToken.balanceOf(address(this.pool))`. 
We know from ERC20 that `balanceOf > 0`.
We also know that `borrowAmount > 0` from the aforementioned `require`.
So, we clearly have that for any `balanceOf`, there exists a `borrowAmount` so that `balanceOf >= borrowAmount`.
That is, the statement is tautological over the space of possible `borrowAmount`s.
This can be removed from our attack surface as well, then.

Let's now consider `assert(poolBalance == balanceBefore)`.
We can see that `poolBalance` comes from using the `depositTokens` function instead of
just directly interacting with `damnValuableToken.transferFrom`; this clearly is our culprit!
That is, this program assumes that `depositTokens` is the only way to change the value of `damnValuableToken`s `poolBalance`.

## Obtaining The Exploit

[Looking through the EIP-20 standard](https://eips.ethereum.org/EIPS/eip-20), ctrlf'ing for 
"transfer", we find the function that we want:

(See [this thread](https://ethereum.stackexchange.com/questions/46457/send-tokens-using-approve-and-transferfrom-vs-only-transfer) for why `transferFrom` isn't appropriate).

[transfer](https://eips.ethereum.org/EIPS/eip-20#transfer)!

This finally leads to our exploit!

```js 
it('Exploit', async function () {
    await this.token.transfer(this.pool.address, 1);
});
```

