const debug = require('debug');
const ChaumPedersen = require('../chaum-pedersen');
const ElGamal = require('basic_simple_elgamal');
const bigInteger = require('big-integer');


const log = debug('app::NIZKP::Chaum-Pedersen::test::BlindFactor');


async function test() {
    const elgamal = new ElGamal()
    await elgamal.initializeRemotely(2048);
    elgamal.checkSecurity();
    log('public key after security checking: ', elgamal.publicKey);

    //ElGamal is ready to use:
    let message = await elgamal.randomGropuMember();
    log('message: ', message);

    /**
     * Encrypt the message:
     */
    let cipherText = await elgamal.encrypt(
        message
    );
    log('cipherText: ', cipherText);

    let secrets = elgamal.export(true);
    
    /**
     * obtain a random blind factor:
     */
    let blindFactor = await elgamal.randomGropuMember();
    log('blind factor: ', blindFactor)

    /**
     * Blind original encryption:
     */
    let sharedSecretBlinder = elgamal.power(blindFactor);
    let messageBlinder = bigInteger(elgamal.publicKey).modPow(blindFactor, elgamal.modulus);

    log('Public key after sharedBlinder computations:', elgamal.publicKey);

    let sharedSecretBlinded = elgamal.multiply(cipherText.c1, sharedSecretBlinder);
    let messageBlinded = elgamal.multiply(cipherText.c2, messageBlinder);
    log('blinder secret: ', elgamal.power(blindFactor));
    log('blinder message: ', bigInteger(elgamal.publicKey).modPow(blindFactor, elgamal.modulus));

    log('Public key after messageBlinder computations:', elgamal.publicKey);

    /**
     * Prepare chaum-pedersen protocol:
     */
    let chaumPedersen = new ChaumPedersen(elgamal);

    log('Public key after initializing ChaumPedersen', elgamal.publicKey);

    log('g^{r+s} = g^r^s: ', 
        sharedSecretBlinded.equals(
            elgamal.power(
                blindFactor.add(secrets.r).mod(elgamal.groupOrder)
            )
        )
    );

    log('g^{r+s}/g^r = g^s: ',
        sharedSecretBlinded.multiply(
            elgamal.power(secrets.r).modInv(elgamal.modulus)
        ).mod(elgamal.modulus).equals(
            elgamal.power(blindFactor)
        )
    );
    
    log('g^{s} verification: ',
    sharedSecretBlinded.multiply(cipherText.c1.modInv(elgamal.modulus)).mod(elgamal.modulus).equals(
        elgamal.power(blindFactor)
    ));

    elgamal.power(blindFactor);
    elgamal.publicKey;
    bigInteger(elgamal.publicKey).modPow(blindFactor, elgamal.modulus);
    log('Public key after all tests: ', elgamal.publicKey);
    /**
     * Prove the correctness of shared secret:
     */
    let proof = await chaumPedersen.prove(
        blindFactor,
        elgamal.power(blindFactor),
        elgamal.publicKey,
        bigInteger(elgamal.publicKey).modPow(blindFactor, elgamal.modulus)
    );

    log('Public key after proof:', elgamal.publicKey)

    log('proof: ', proof);

    let result = chaumPedersen.verify(
        proof,
        sharedSecretBlinded.multiply(cipherText.c1.modInv(elgamal.modulus)).mod(elgamal.modulus),
        elgamal.publicKey,
        messageBlinded.multiply(cipherText.c2.modInv(elgamal.modulus)).mod(elgamal.modulus)
    );
    
/* 
    log('y^{s}: ', 
    sharedSecretBlinded.multiply(cipherText.c1.modInv(elgamal.modulus)).mod(elgamal.modulus).equals(
        elgamal.power(blindFactor)
    )
    );
    
    log('g^{s}: ',    
        messageBlinded.multiply(cipherText.c2.modInv(elgamal.modulus)).mod(elgamal.modulus).equals(
            messageBlinded.multiply(cipherText.c2.modInv(elgamal.modulus)).mod(elgamal.modulus)
        )
    )
 */
    log('Verify: ', result);
}


test();