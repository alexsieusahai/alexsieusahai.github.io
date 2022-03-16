---
layout: post
title:  Damn Vulnerable DeFi - Unstoppable
categories: [DeFi, Solidity, DVDF]
excerpt: Writeup for Naive Receiver.
---
# Naive Receiver

First off, [the pwnable is here](https://www.damnvulnerabledefi.xyz/challenges/1.html). I'll be talking from the perspective of someone with some exploit dev experience (say, completion of [pwncollege](https://pwn.college/)), but with basically no Solidity nor DeFi experience.

[Solidity By Example](https://docs.soliditylang.org/en/v0.8.0/solidity-by-example.html) is pretty good for giving a basic introduction to the language and will be assumed.

## What Do We Have To accomplish?

We have to somehow make the following pass:
```js
after(async function () {
    /** SUCCESS CONDITIONS */

    // All ETH has been drained from the receiver
    expect(
        await ethers.provider.getBalance(this.receiver.address)
    ).to.be.equal('0');
    expect(
        await ethers.provider.getBalance(this.pool.address)
    ).to.be.equal(ETHER_IN_POOL.add(ETHER_IN_RECEIVER));
});
```

In particular, then, we must somehow find a way to move the funds from the
receiver into the pool (which imo is a dead giveaway but I digress).

## Defining The Attack Surface

The culprit function must exist, then, somewhere within `NaiveReceiverLenderPool`.
Thankfully, there's only one function within that contract; `flashLoan`!
Speaking within the context of that function:
+ `borrower` has no restrictions on what it is other than its datatype, `address`, and the fact that it's a contract
+ We give the ETH and control flow to `borrower`, which does stuff
+ We're guaranteed by the following:
```solidity
require(
    address(this).balance >= balanceBefore + FIXED_FEE,
    "Flash loan hasn't been paid back"
);
```
that we get those funds back, plus the `FIXED_FEE` which is 1 ETH.

That is, we essentially take 1 ETH from borrower and give it to the pool every
time we execute a flash loan, and borrower's only restriction is that it must
be a contract.

This is it!

## Obtaining The Exploit

We can just call `this.pool.flashLoan` 10 times, with a (basically) arbitrary
borrow amount, with our `this.receiver` as the `borrower`. 
This results in 10 ETH in total being transferred from `this.receiver` to `this.pool`, as required.

```js
it('Exploit', async function () {
  for (let i = 0; i < 10; ++i)
      this.pool.flashLoan(this.receiver.address, 1);
});
```
