/**
 * Prover class:
 * @module ./prover
 */


const ElGamal = require('basic_simple_elgamal');
const bigInteger = require('big-integer');
const crypto = require('crypto');
const debug = require('debug');


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


const log = debug('app::NIZKP::Chaum-Pedersen::Prover');
const hash = crypto.createHash('SHA3-512');


/**
 * This class is Chaum-Pedersen prover.
 * The prover works upon an cyclic group and to be more accurate, it works on a multiplicative
 * group which is specified by (g, p) pair where 'g' is generator and 'p' is modulus.
 */
class Prover{
    /**
     * Initialize the prover with a multiplicative group.
     * Please note: though the argument is type of ElGamalInfo but this module can be used in
     * any field which uses Discrete Logarithm as its basis.
     * So don't worry about 'ElGamal' word, just pass an object which contains g as Generator
     * and p as Modulus.
     * @param {ElGamalInfo} groupInfo - The essential info for underlying Multiplicative group
     * which should contains Generator g and Modulus p.
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
     * Use this method to prove that secret power of m and n is equal and you know it.
     * Based on Chaum-Pedersen protocol, the passed arguments should be in below form:
     *      x = g^{r} mod p
     *      m = n^{r} mod p
     * @async
     * @param {string|bigInteger.BigInteger} r - The secret which you want to prove your knowledge about it.
     * @param {string|bigInteger.BigInteger} x - The first public info which is computed by modular exponentiation.
     * @param {string|bigInteger.BigInteger} n - The base of second modular exponentiation.
     * @param {string|bigInteger.BigInteger} m - The second public info which is computed by modular exponentiation.
     * @returns {Promise<Proof>} - The resulted Chaum-Pedersen NIZKP.
     * @throws Will throw an error if any parameter is of wrong type
     */
    async prove(r, x, n, m){
        //Convert all parameters to big-integer:
        if(typeof r === 'string')
            r = bigInteger(r);
        else if(! (r instanceof bigInteger))
            throw new Error('Wrong type of r passed, it should be of type big-integer or string.');
        if(typeof x === 'string')
            x = bigInteger(x);
        else if(! (x instanceof bigInteger))
            throw new Error('Wrong type of x passed, it should be of type big-integer or string.');
        if(typeof n === 'string')
            n = bigInteger(n);
        else if(! (n instanceof bigInteger))
            throw new Error('Wrong type of n passed, it should be of type big-integer or string.');
        if(typeof m === 'string')
            m = bigInteger(m);
        else if(! (m instanceof bigInteger))
            throw new Error('Wrong type of m passed, it should be of type big-integer or string.');
        
        //Compute U:
        let commitment = await this.elgamal.randomGropuMember();
        let U = this.elgamal.power(commitment);

        //Compute V:
        let V = n.modPow(commitment, this.elgamal.modulus);

        /**
         * Apply the Fiat-Shamir heuristic:
         *  Pass necessary inputs so that to use "Strong" Fiat-Shamir heuristic.  
        */ 
        hash.update(this.elgamal.generator);
        hash.update(x.toString());
        hash.update(m.toString());
        hash.update(U.toString());
        hash.update(V.toString());

        // Compute hash:
        let h = hash.digest('hex');

        /**
         * Numerical representation of hash:
         */
        let nrc = bigInteger(h, 16);

        // Compute Response:
        let response = commitment.add(nrc.negate().multiply(r)).mod(this.elgamal.groupOrder);

        return {
            U,
            V,
            response
        };
    }
    
}


/**
 * Prover class
 */
module.exports = Prover;