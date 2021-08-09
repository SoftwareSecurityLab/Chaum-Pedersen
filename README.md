- [Chaum-Pedersen NIZKP](#chaum-pedersen-nizkp)
- [Installation](#installation)
- [Usage](#usage)
  - [Methods](#methods)
    - [`ChaumPedersen(p)`](#chaumpedersenp)
    - [`ChaumPedersen(p, g)`](#chaumpedersenp-g)
    - [`prove(r, x, n, m)`](#prover-x-n-m)
    - [`verify(proof, x, n, m)`](#verifyproof-x-n-m)
- [Example](#example)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)

# Chaum-Pedersen NIZKP

The non-interactive version of [original Chaum-Pedersen zero-knowledge proof][cp].  
This project is purposed to be used with public key cryptosystem based on "Discrete Logarithm" such as ElGamal.

>Chaum-Pedersen proof is used to prove the equality of exponents of two modular exponentiation with different bases.

The strong [Fiat-Shamir heuristic][fsh] is applied to Chaum-Pedersen protocol to make it non-interactive.

> NIZKP stands for 'Non-Interactive Zero-Knowledge Proof'

You should first initialize the module with a [Cyclic Group][cg] then it's ready.  
This module works over [Multiplicative Group][mg] of integers as underlying [Cyclic Group][cg].

**NOTE:** The Module is developed for educational goals, although we developed it securely but the risk of using it in production environment is on you!

# Installation

Either you are using [Node.js][nj] or a browser, you can use it locally by downloading it from [npm][np]: 
```
npm install @software-security-lab/chaum-pedersen
```

# Usage 

To include this module in your code simply:

```
const ChaumPedersen = require('@software-security-lab/chaum-pedersen');
```

If you are using it in a browser, you may need to use a tool such as [browserify][by] to compile your code.

After including the module into your code, you can create your instance using `new` operator as described in [Methods](#methods) section.

## Methods

While introducing the methods, we use specific phrases which are listed below:
* **Throws Error:** Indicates the methods throw an error, the type or reason of possible errors is explained in the method's explanation.
* **Async:** Indicates this method is an asynchronous method which means you should wait for it to complete its execution.

### `ChaumPedersen(p)`
* **`p`:** [`ElGamal`][ourelg]
* **Returns:** NIZKP Chaum-Pedersen module
* **Throws Error:**

If you are using our [ElGamal][ourelg] module, you can directly pass your instance and then use it to proof your secret of knowledge.

`p` parameter is your instance of [`ElGamal`][ourelg] module:

```
const elgamal = new ElGamal();
await elgamal.initializeRemotely(2048);
elgamal.checkSecurity();
let chaumPedersen = new ChaumPedersen(elgamal);
```

Throws an error if `p` is of wrong type.

### `ChaumPedersen(p, g)`
* **`p`:** `String` | [`big-integer`][bi]
* **`g`:** `String` | [`big-integer`][bi]
* **Returns:** NIZKP Chaum-Pedersen Proof.
* **Throws Error:**

If you're not using [ElGamal][ourelg] module and even not [ElGamal Encryption][eg], you can initialize the Chaum-Pedersen this way.

`p` parameter is the modulus of underlying [Cyclic Group][cg].  
`g` parameter is the generator of underlying [Cyclic Group][cg].  
Throws an error if one of `p` or `g` is not provided or is of wrong type.

> Keep in mind the Chaum-Pedersen works over [Cyclic Group][cg] which can be determined by its generator and order.
> Since we are using [Multiplicative Groups][mg] as [Cyclic Groups][cg], modulus `p` specifies the group order implicitly.

### `prove(r, x, n, m)`
* **`r`:** `String` | [`big-integer`][bi]
* **`x`:** `String` | [`big-integer`][bi]
* **`n`:** `String` | [`big-integer`][bi]
* **`m`:** `String` | [`big-integer`][bi]
* **Returns:** Chaum-Pedersen Proof
* **Async**
* **Throws Error**

Produces a Chaum-Pedersen proof for you which you can use to prove your knowledge about secret `r`.

`r` is your secret which you wants to prove your knowledge about it without revealing it.  
`x` is the result of first modular exponentiation:  
$\qquad$ `g` <sup>`r`</sup> `mod p = x`  
`n` is base of your second modular exponentiation.  
`m` is the result of second modular exponentiation:  
$\qquad$ `n` <sup>`r`</sup> `mod p = m`

Throws an error if any of parameters is of wrong type.

**NOTE:** For security sakes, we get rid of `r` as soon as we computes the Chaum-Pedersen proof. So make sure you keep it safe yourself.

### `verify(proof, x, n, m)`
* **`proof`:** Chaum-Pedersen Proof
* **`x`:** `String` | [`big-integer`][bi]
* **`n`:** `String` | [`big-integer`][bi]
* **`m`:** `String` | [`big-integer`][bi]
* **Returns:** boolean
* **Throws Error**

Verifies the knowledge of prover about equality of exponents of both modular exponentiation considering receiving `proof`.

`proof` is resulted from calling [`prove()`](#prover-x-n-m) method.  
`x` is the result of first modular exponentiation:  
$\qquad$ `g` <sup>`r`</sup> `mod p = x`  
`n` is base of your second modular exponentiation.  
`m` is the result of second modular exponentiation:  
$\qquad$ `n` <sup>`r`</sup> `mod p = m`

Returns `true` if knowledge of prover about `r` is verified and returns `false` otherwise.

Throws an error if any of parameters is of wrong type.

# Example

One of the most usage of Chaum-Pedersen proof is verifying the validity of blind factor in [blinding operations][blinding].

Hence we provided an example at [`./tests/blindFactorProof.js`][test] which shows you how you can use this module to verify blinding operation in [ElGamal Cryptosystem][eg].

# Contributing
Since this module is developed at [Software Security Lab][softsl], you can pull requests but merging it depends on [Software Security Lab][softsl] decision.  
Also you can open issues first then we can discuss about it.

# Support
If you need help you can either open an issue in [GitHub page][gitpage] or contact the developers by mailing to golgolniamilad@gmail.com

# License
This work is published under [ISC][isc] license.


[cp]: https://en.wikipedia.org/wiki/Publicly_Verifiable_Secret_Sharing#Chaum-Pedersen_Protocol
[fsh]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
[cg]: https://en.wikipedia.org/wiki/Cyclic_group
[mg]: https://en.wikipedia.org/wiki/Multiplicative_group
[np]: https://www.npmjs.com/
[nj]: https://nodejs.org/en/
[by]: https://browserify.org/
[ourelg]: https://www.npmjs.com/package/basic_simple_elgamal
[bi]: https://www.npmjs.com/package/big-integer
[blinding]: https://en.wikipedia.org/wiki/Blinding_(cryptography)
[eg]: https://en.wikipedia.org/wiki/ElGamal_encryption
[gitpage]: https://github.com/SoftwareSecurityLab/Chaum-Pedersen.git
[softsl]: https://github.com/SoftwareSecurityLab
[isc]: ./LICENSE
[tmail]: mailto:maryam.mouzarani@gmail.com
[test]: ./tests/blindFactorProof.js