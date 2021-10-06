/**
 * Chaum-Pedersen module:
 * @module ./chaum-pedersen
 */


const ElGamal = require('basic_simple_elgamal');
const Prover = require('./modules/prover');
const Verifier = require('./modules/verifier');
const bigInteger = require('big-integer');
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


const log = debug('app::NIZKP::Chaum-Pedersen');


/**
 * The class which integrate the prover and verifier both together and Implements
 * the Chaum-Pedersen protocol at once.
 * Though this module works upon ElGamal engine but don't worry! if you use discrete logarithm 
 * and you want to prove the secret, you can use this module too. As matter of fact you even don't
 * need to know what is ElGamal and how it works.
 * Also you should note that this module just works upon Multiplicative groups!
 */
class ChaumPedersen{
    /**
     * Initialize the Chaum-Pedersen protocol with multiplicative group which you use it in your
     * computations. you can initialize Chaum-Pedersen by passing an instance of your ElGamal engine
     * if you have one or initialize with the Modulus and Generator separately.
     * @param {ElGamal|string|bigInteger.BigInteger} p - The ElGamal engine or the modulus of the
     * multiplicative group, if you pass ElGamal engine then you can leave the g as undefined.
     * @param {string|bigInteger.BigInteger} [g] - The generator of the underlying multiplicative 
     * group
     */
    constructor(p, g){
        let generator = undefined;
        let modulus = undefined;

        if(p instanceof ElGamal){
            generator = p.generator;
            modulus = p.modulus;
        }else if(typeof p === 'string')
            modulus = bigInteger(p);
        else if(p instanceof bigInteger)
            modulus = p;
        else 
            throw new Error(`Wrong type of modulus passed, it should be either of type string,
            big-integer or ElGamal`);

        if(generator === undefined){
            if(typeof g === 'string')
                generator = bigInteger(g);
            else if(g instanceof bigInteger)
                generator = g;
            else 
                throw new Error(`Wrong type of Generator passed, it should be either type string
                or big-integer.`);
        }

        /**
         * @property {Prover} prover - The underlying Prover Class, You don't need to use it directly.
         */
        this.prover = new Prover({
            p: modulus,
            g: generator
        });

        /**
         * @property {Verifier} verifier - The underlying Verifier Class, You don't need to use it directly.
         */
        this.verifier = new Verifier({
            p: modulus,
            g: generator
        });
    }


    /**
     * Prove the secret exponent of 'm' is equal to secret exponent of 'x' and also prove that 
     * you know its value.
     * Based on Chaum-Pedersen protocol, the passed arguments should be in below form:
     *      x = g^{r} mod p &
     *      m = n^{r} mod p
     * @async
     * @param {bigInteger.BigInteger|string} r - The secret which you want to prove your knowledge
     * about it. 
     * @param {bigInteger.BigInteger|string} x - The first public info which is computed by modular
     * exponentiation. 
     * @param {bigInteger.BigInteger|string} n - The base of second modular exponentiation. 
     * @param {bigInteger.BigInteger|string} m - The second public info which is computed by modular
     * exponentiation.
     * @param {bigInteger.BigInteger|string} [g = g] - The base of first modular exponentiation. Default
     * value is generator of cyclic group.
     * @returns {Promise<Proof>} - The resulted Chaum-Pedersen.
     * @throws Will throw an error if any of parameters is of wrong type. 
     */
    async prove(r, x, n, m, g){
        return (await this.prover.prove(r, x, n, m, g));
    }


    /**
     * Use this method to verify that prover knows the secret exponent of x and m and it is equal
     * for both of them.
     * Based on Chaum-Pedersen proof the passed parameters should be in below form:
     *      x = g^{secret} mod p &
     *      m = n^{secret} mod p
     * @param {Proof} proof - The Chaum-Pedersen proof which is obtained by calling prove() method. 
     * @param {bigInteger.BigInteger|string} x - The first public info which you want to prove 
     * your knowledge about its secret. 
     * @param {bigInteger.BigInteger|string} n - The base of modular exponentiation in second
     * public info 
     * @param {bigInteger.BigInteger|string} m - The second public info which you want to verify 
     * your knowledge about its secret exponent.
     * @param {bigInteger.BigInteger|string} [g = g] - The base of first modular exponentiation. Default
     * value is generator of cyclic group.
     * @returns {boolean} - Returns true if the provers knowledge verified and false otherwiase.
     * @throws Will throw an error if any of argument is of wrong type.
     */
    verify(proof, x, n, m, g){
        return this.verifier.verify(proof, x, n, m, g);
    }

}


/**
 * Chaum-Pedersen Class:
 */
module.exports = ChaumPedersen;