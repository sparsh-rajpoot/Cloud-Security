const crypto = require('crypto');

let decrypted_results = new Array();


module.exports = { 
    
    // generating key using ecdh
    ecdh_keygenerate: function() {
        var key = ecdh_keygenerate_function();
        return key;
    },

    // encrypting message using aes 256
    aes_encrypt: function(message, message_array, key) {
        aes_encrypt_function(message, message_array, key);
        return message_array;
    },

    // decrypting message using aes 256
     aes_decrypt: function(array, key) {
        var decrypted_message = aes_decrypt_function(array, key);
        return decrypted_message;
     },

     
     // encrypting aes encrypted text using blowfish encryption
     blowfish_encrypt: function(aes_encrypted_message, key) {
        blowfish_encrypted_message = blowfish_encrypt_function(aes_encrypted_message, key);
        return blowfish_encrypted_message;
     },

     // decrypting blowfish encrypted text 
     blowfish_decrypt: function(blowfish_encrypted_message, key) {
         var blowfish_decrypted_message = blowfish_decrypt_function(blowfish_encrypted_message, key);
         return blowfish_decrypted_message;
     }

};

function ecdh_keygenerate_function() {
    //ECDH

    const alice = crypto.createECDH('secp256k1');
    alice.generateKeys()

    const bob = crypto.createECDH('secp256k1');
    bob.generateKeys()


    const alicePublicKeyBase64 = alice.getPublicKey().toString('base64')
    const bobPublicKeyBase64 = bob.getPublicKey().toString('base64')


    const aliceSharedKey = alice.computeSecret(bobPublicKeyBase64, 'base64', 'hex')
    const bobSharedKey = bob.computeSecret(alicePublicKeyBase64, 'base64', 'hex')

    if(aliceSharedKey == bobSharedKey)
    return aliceSharedKey;
}


function aes_encrypt_function(message, message_array, key) {
    const IV = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), IV);

    let encrypted = cipher.update(message, 'utf8', 'hex')
    encrypted += cipher.final('hex')

    const auth_tag = cipher.getAuthTag().toString('hex')

    message_array.push(encrypted, IV.toString('hex'), auth_tag);
}


function aes_decrypt_function(array, key) {
    try {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            Buffer.from(key, 'hex'),
            Buffer.from(array[1], 'hex')
        );

        decipher.setAuthTag(Buffer.from(array[2], 'hex'))
    
        let decrypted = decipher.update(array[0], 'hex', 'utf8')
        decrypted += decipher.final('utf8');
    
        return decrypted;
    }  catch (error) {
        console.log(error.message);
    }
}

//BLOWFISH

function blowfish_encrypt_function(aes_encrypted_message, key) {
    const Blowfish = require('./javascript-blowfish');
    const bf = new Blowfish(key);
    const Encrypted = bf.encrypt(aes_encrypted_message)
    let EncryptedMime = bf.base64Encode(Encrypted)
    return EncryptedMime;
}

function blowfish_decrypt_function(blowfish_encrypted_message, key) {
    const Blowfish = require('./javascript-blowfish');
    const bf = new Blowfish(key);
    return bf.decrypt(bf.base64Decode(blowfish_encrypted_message))
}



// const Blowfish = require('javascript-blowfish');

// const Key = aliceSharedKey;
// const bf = new Blowfish(Key);

// console.log("Blowfish encrypt text by key: " + Key);

// // Encryption
// const Encrypted = bf.encrypt(encrypted)
// let EncryptedMime = bf.base64Encode(Encrypted)
// console.log(EncryptedMime);

// // Decryption
// console.log(
//     'decrypted: ',
//     bf.decrypt(
//         bf.base64Decode(EncryptedMime)
//     )
// );

