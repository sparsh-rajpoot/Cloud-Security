const NodeRSA = require('node-rsa');

let rsa_keys_array = new Array();

module.exports = {
    rsa_keygenerate: function() {
        rsa_keygenerate_function()
        return rsa_keys_array
    },


    rsa_encrypt: function(message, public_key) {
        var rsa_encrypted_message = rsa_encrypt_function(message, public_key)
        return rsa_encrypted_message
    },

    rsa_decrypt: function(rsa_encrypted_message, private_key) {
        var rsa_decrypted_message = rsa_decrypt_function(rsa_encrypted_message, private_key)
        return rsa_decrypted_message
    },
}


function rsa_keygenerate_function() {
    
    const key = new NodeRSA({b: 1024})
    const public_key = key.exportKey('public')
    const private_key = key.exportKey('private')

    // var public_key_without_banner = new String(public_key)
    // public_key_without_banner = public_key_without_banner.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').trim()

    // var private_key_without_banner = new String(private_key)
    // private_key_without_banner = private_key_without_banner.replace('-----BEGIN RSA PRIVATE KEY-----', '').replace('-----END RSA PRIVATE KEY-----', '').trim()

    rsa_keys_array.push(public_key, private_key)
}

function rsa_encrypt_function(message, public_key) {
    let key_public = new NodeRSA(public_key)
    var encrypted = key_public.encrypt(message, 'base64');
    return encrypted    
}


function rsa_decrypt_function(rsa_encrypted_message, private_key) {
    let key_private = new NodeRSA(private_key)

    var decrypted = key_private.decrypt(rsa_encrypted_message, 'utf-8');
    return decrypted
}