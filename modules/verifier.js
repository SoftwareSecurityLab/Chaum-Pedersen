/**
 * Verifier module:
 * @module ./verifier
 */


const ElGamal = require('basic_simple_elgamal');
const bigInteger = require('big-integer');
const debug = require('debug');
const crypto = require('crypto');


/**
 * @typedef {Object} Proof - The NIZK Chaum-Pedersen proof.
 * @property {bigInteger.BigInteger|string} U - The first commitment which is made randomly
 * by prover.
 * @property {bigInteger.BigInteger|string} V - The second commitment which is made randomly
 *  by prover
 * @property {bigInteger.BigInteger|string} response - The response which contains the secret 
 * knowledge r and is used to prove the knowledge of secret.
 */
/**
 * @typedef {'HIGH'|'LOW'|'MEDIUM'} securityLevel
 */
/**
 * @typedef {Object} ElGamalInfo the object containing essential information to build the ElGamal
 *  cryptoengine again
 * @property {bigInteger.BigInteger|string} p - The modulus of underlying group and determine the whole Cyclic group
 * @property {bigInteger.BigInteger|string} g - The generator of underlying group.
 * @property {bigInteger} [y] - The public key which is your public key and others can use it to 
 * encrypt messages for you.
 * @property {bigInteger} [x] - The private key(decryption key) which is strongly recommended to don't export it
 * @property {bigInteger} [r] - The secret key which is used in last encryption to build 
 * the cipherText.c1
 * @property {securityLevel} [security] - The engine security level.
 */


const log = debug('app::NIZKP::Chaum-Pedersen::Verifier');
const hash = crypto.createHash('SHA3-512');


/**
 * The Chaum-Pedersen Verifier Class.
 * The verifier works upon an cyclic group and to be more accurate, it works on a multiplicative
 * group which is specified by (g, p) pair where 'g' is generator and 'p' is modulus.
 */
class Verifier{
    /**
     * Initialize the verifier with a multiplicative group.
     * Please note: Though the argument is type of ElGamalInfo but this module can be used in 
     * any field which usess Discrete Logarithm as its basis.
     * So don't worry about 'ElGamal' word, just pass an object which contains g as Generator
     * and p as Modulus.
     * @param {ElGamalInfo} groupInfo - The essential info for underlying multiplicative group
     * which should contains Generator 'g' and Modulus 'p'.
     */
    constructor(groupInfo){
        /**
         * @property {ElGamal} elgamal -The underlying ElGamal Engine which is used to create
         * Multiplicative group and perform modular operations upon it.
         * NOTE: Don't use it directly!
         */
        this.elgamal = new ElGamal(groupInfo.p, groupInfo.g);
    }

    /**
     * Use this method to verify that prover knows the secret exponent of x and m and it is equal
     * for both of them.
     * Based on Chaum-Pedersen proof the passed parameters should be in below form:
     *      x = g^{secret} mod p
     *      m = n^{secret} mod p
     * @param {Proof} proof The Chaum-Pedersen proof which is obtained by calling prover.prove().
     * @param {string|bigInteger.BigInteger} x - The first public info which you want to prove
     * your knowledge about its secret.
     * @param {string|bigInteger.BigInteger} n - The base of modular exponentiation in second
     * publi info..
     * @param {string|bigInteger.BigInteger} m - The second public info which you want to prove
     * your knowledge about its secret exponenet.
     * @returns {boolean} - Returns true if the provers knowledge verified and false otherwise.
     * @throws Will throw an error if any of argument is of wrong type.
     */
    verify(proof, x, n, m){
        /**
         * Unify type of arguments:
         */
        if(typeof x === 'string')
            x = bigInteger(x);
        else if(!(x instanceof bigInteger))
            throw new Error('Wrong type of x passed, it should be of type string or big-integer.');
        if(typeof n === 'string')
            n = bigInteger(n);
        else if(! (n instanceof bigInteger))
            throw new Error('Wrong type of n passed, it should be of type string or big-integer.');
        if(typeof m === 'string')
            m = bigInteger(m);
        else if(! (m instanceof bigInteger))
            throw new Error('Wrong type of m passed, it should be of type string or big-integer.');
        
        /**
         * Pass correct parameters to hasing function:
         */
        hash.update(this.elgamal.generator);
        hash.update(x.toString());
        hash.update(m.toString());
        hash.update(proof.U.toString());
        hash.update(proof.V.toString());

        // Compute hash:
        let h = hash.digest('hex');

        /**
         * Numerical representation of hash:
         */
        let nrc = bigInteger(h, 16);

        /**
         * Unify types of proof constituents
         */
        if(typeof proof.U === 'string')
            proof.U = bigInteger(proof.U);
        if(typeof proof.V === 'string')
            proof.V = bigInteger(proof.V);
        if(typeof proof.response === 'string')
            proof.response = bigInteger(proof.response);
        
        /**
         * g^{r*nrc}:
         */
        let grnrc = x.modPow(nrc, this.elgamal.modulus);

        /**
         * n^{r*nrc}:
         */
        let nrnrc = m.modPow(nrc, this.elgamal.modulus);

        /**
         * g^{response}*x^{nrc}:
         */
        let computedU = this.elgamal.power(proof.response);
        computedU = this.elgamal.multiply(computedU, grnrc);

        /**
         * n^{response}*m^{nrc}:
         */
        let computedV = this.elgamal.power(proof.response);
        computedV = this.elgamal.multiply(computedV, nrnrc);

        return proof.U.equals(computedU) && proof.V.equals(computedV);
    }
}


/**
 * Verfier Class:
 */
module.exports = Verifier;