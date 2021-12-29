const crypto = require('crypto');


module.exports = {
    // decrypting blowfish encrypted text 
    blowfish_decrypt: function(blowfish_encrypted_message, key) {
        var blowfish_decrypted_message = blowfish_decrypt_function(blowfish_encrypted_message, key);
        return blowfish_decrypted_message;
    },

    // decrypting message using aes 256
    aes_decrypt: function(name, iv, auth_tag, key) {
        var decrypted_message = aes_decrypt_function(name, iv, auth_tag, key);
        return decrypted_message;
    },

    rsa_decrypt: function(rsa_encrypted_message, private_key) {
        var rsa_decrypted_message = rsa_decrypt_function(rsa_encrypted_message, private_key)
        return rsa_decrypted_message
    },
}

function blowfish_decrypt_function(blowfish_encrypted_message, key) {
    const Blowfish = require('./javascript-blowfish');
    const bf = new Blowfish(key);
    return bf.decrypt(bf.base64Decode(blowfish_encrypted_message))
}


function aes_decrypt_function(name, iv, auth_tag, key) {
    try {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            Buffer.from(key, 'hex'),
            Buffer.from(iv, 'hex')
        );

        decipher.setAuthTag(Buffer.from(auth_tag, 'hex'))
    
        let decrypted = decipher.update(name, 'hex', 'utf8')
        decrypted += decipher.final('utf8');
    
        return decrypted;
    }  catch (error) {
        console.log(error.message);
    }
}


function rsa_decrypt_function(rsa_encrypted_message, private_key) {
    const NodeRSA = require('node-rsa');

    let key_private = new NodeRSA(private_key)

    var decrypted = key_private.decrypt(rsa_encrypted_message, 'utf-8');
    return decrypted
}