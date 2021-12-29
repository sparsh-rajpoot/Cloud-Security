// required libraries and files
//-------------------------------
const express = require('express');
const mysql = require("mysql");
const path = require('path');
const dotenv = require('dotenv');
var bodyParser = require('body-parser');
const rsa = require('./rsa');
const encryption = require('./encryption');
const { dirname } = require('path');
const perf = require('execution-time')();
var zip = require('express-zip');
const decryption = require('./decryption');
const { measureMemory } = require('vm');
const { memoryUsage } = require('process');

// just some necessary setups for nodejs 

dotenv.config({ path: './.env'});

const app = express();

//body parser enables us to retrieve value of variable from (req.body)
// syntax to retrieve value => req.body.variable_name
app.use(bodyParser.urlencoded({ extended: true })); 
app.use(bodyParser.json())




// creating mysql object to use mysql
const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});



//this is a route in which user is redirected if user clicks on encrpyt button on the index page
// this encrypt is responsible for encryption and saving the data into database
app.use("/encrypt", function(req, res, next)  {        //when user clicks on encrypt on index page

    //---------------------------------------------------------------------------------------------------------------
    const firstname = req.body.firstname;
    const lastname = req.body.lastname;
    const email = req.body.email;

    // console.table(
    //     [firstname, lastname, email                   //printing the values received from the user on index page
    //     ]
    // )

    //----------------------------------------------------------------------------------------------------------------



    // ECDH + AES + BLOWFISH
    //-------------------------------------------------------------------------------------------------------------------------------------------

    perf.start();                       // start timer for hybrid decryption

    // Generating key using ECDH
    var key = encryption.ecdh_keygenerate();

    // encrypting firstname and lastname using aes encryption
    let aes_encrypted_fn_array = new Array();              // this array stores aes encrypted firstname, firstname_iv and firstname_auth_tag  (order is exactly same in the array as i wrote here)
    let aes_encrypted_ln_array = new Array();              // this array stores aes encrypted lastname, lastname_iv and lastname_auth_tag     (order is exactly same in the array as i wrote here)
    aes_encrypted_fn_array = encryption.aes_encrypt(firstname, aes_encrypted_fn_array, key);
    aes_encrypted_ln_array = encryption.aes_encrypt(lastname, aes_encrypted_ln_array, key);


    //encrypting aes text using blowfish
    const blowfish_encrypted_fn = encryption.blowfish_encrypt(aes_encrypted_fn_array[0], key);          
    const blowfish_encrypted_ln = encryption.blowfish_encrypt(aes_encrypted_ln_array[0], key);
    
    var hybrid_encrypt_time = perf.stop().time;                // stop timer for hybrid encryption



    // // printing ecdh key
    // console.log("This is your key. Please dont forget this key or you will be doomed = " + key);

    // // printing aes encrypted msg
    // console.table (
    //     ["aes_encrypted_firstname = " + aes_encrypted_fn_array[0],
    //     "aes_encrypted_firstname_iv = " + aes_encrypted_fn_array[1],
    //     "aes_encrypted_firstname_auth_tag = " + aes_encrypted_fn_array[2],
    //     "aes_encrypted_lastname = " + aes_encrypted_ln_array[0],
    //     "aes_encrypted_lastname_iv = " + aes_encrypted_ln_array[1],
    //     "aes_encrypted_lastname_auth_tag = " + aes_encrypted_ln_array[2],
    //     ]
    // )

    // //printing blowfish encrypted msg
    // console.table(
    //     ["blowfish_encrypted_firstname = " + blowfish_encrypted_fn,
    //     "blowfish_encrypted_lastname = " + blowfish_encrypted_ln,
    //     ])


    //-------------------------------------------------------------------------------------------------------------------------------------------




    //-----------------------------------------------------------------------------------------------------------------------------------------
    // RSA

    perf.start();      // start timer for rsa encryption

    let rsa_keys = new Array();             //array to store the rsa public and private keys
    
    rsa_keys = rsa.rsa_keygenerate();       // generating rsa public and private keys 


    // encrypting firstname and lastname using rsa
    const rsa_encrypted_fn = rsa.rsa_encrypt(firstname, rsa_keys[0])          // rsa_keys[0] => rsa_public_key
    const rsa_encrypted_ln = rsa.rsa_encrypt(lastname, rsa_keys[0])

    var rsa_encrypt_time = perf.stop().time;           // stop timer for rsa encryption
    

    // printing the rsa_encrypted data and rsa keys

    // console.table (
    //     ["rsa_encrypted_firstname = " + rsa_encrypted_fn,
    //     "rsa_encrypted_lastname = " + rsa_encrypted_ln,
    //     ]
    // )
    // console.log("public key" + rsa_keys[0])
    // console.log("private key" + rsa_keys[1])                // rsa_keys[1] => rsa_private_key


    //-------------------------------------------------------------------------------------------------------------------------------------------




    // inserting encrypted data into rsa database
    //-------------------------------------------------------------------------------------------------------------------------------------------

    db.query('SELECT email FROM rsa WHERE email = ?', [email], (error, results) => {
        if(error) {
            console.log(error);
        }
    
        if(results.length > 0) {
            return res.render('index', {
                message: 'This email address already exists'
            });
        }
    
        else {
            db.query('INSERT INTO rsa SET ?', {firstname: rsa_encrypted_fn, lastname: rsa_encrypted_ln, email: email, public_key: rsa_keys[0]}, (error, results) => {
                if(error){
                    console.log(error);
                } else {
                    res.rsa_key = rsa_keys[1];
                    res.ecdh_key = key;
                }
            })
        }
    })

    //-------------------------------------------------------------------------------------------------------------------------------------------



    // inserting encrypted data into hybrid database
    //-------------------------------------------------------------------------------------------------------------------------------------------

    // checking if the email already exists
    db.query('SELECT email FROM hybrid WHERE email = ?', [email], (error, results) => {
        if(error) {
            console.log(error);
        }
    
        if(results.length > 0) {           // if result length is greater than 1. It means that the email is already present. so throw an error and dont save the data again
            return res.render('index', {
                message: 'This email address already exists'
            });
        }
    
        else {              // if email is not present in the database
            // mysql query to insert the data of hybrid encryption into the database
            db.query('INSERT INTO hybrid SET ?', {firstname: blowfish_encrypted_fn, lastname: blowfish_encrypted_ln, email: email, firstname_iv: aes_encrypted_fn_array[1], firstname_auth_tag: aes_encrypted_fn_array[2], lastname_iv: aes_encrypted_ln_array[1], lastname_auth_tag: aes_encrypted_ln_array[2]}, (error, results) => {
                if(error){
                    console.log(error);
                } else {
                    res.rsa_encrypt_time = rsa_encrypt_time,
                    res.hybrid_encrypt_time = hybrid_encrypt_time
                    return next();                                              // if we are able to successfully insert the data into database then goto next /encrypt.  using middleware concept here
                } 
            })
        }
    })

    //-------------------------------------------------------------------------------------------------------------------------------------------

});

// this function is responsible for creating and writing rsa and hybrid text files 
// using middlware here. next() is transferring the program flow here
app.use('/encrypt', function(req, res) {                               
    fs = require('fs')                                                      
    fs.writeFile('rsa_key.txt', res.rsa_key, function (err) {                   // creating and  writing rsa.txt
        if (err) return console.log(err);
        console.log('rsa_key sucessfully created');
    });

    fs.writeFile('ecdh_key.txt', res.ecdh_key, function (err) {                // creating and writing ecdh.txt
        if (err) return console.log(err);
        console.log('ecdh key successfully created');
    });

    res.render("encrypt_success", {rsa_encrypt_time: res.rsa_encrypt_time,                 // after successfully creating file we are calling encrypt_success
        hybrid_encrypt_time: res.hybrid_encrypt_time,  
        ecdh_key: res.ecdh_key,
        rsa_key: res.rsa_key,
        message: "data is successfully stored"
    })
});



// if user clicks on decrypt on index page. user redirects to this route and the function starts
// this function is responsible for retrieving the hybrid encrypted data from the database
app.use('/decrypt', function(req, res, next) {                                      
    var email_id = req.body.email_id
    db.query('SELECT * FROM hybrid WHERE email = ?', email_id, function(error, results) {                // rertireving hybrid encryption data from the database
        if(error){
            res.send(error)
        }

        else if(results.length){
            res.email_id = email_id                        // this is for next /decrypt to use the res data. middleware thing
            res.hybrid_results = results                   // res.hybrid_results = results  is storing the results of query into res.hybrid_results
            res.ecdh_key = req.body.ecdh_Key
            res.rsa_priv_key = req.body.rsa_priv_key       // we are saving responses for next() /decrypt to use it later
            res.email_id = req.body.email_id
            return next();                                // calling next /decrypt
        }

        else {
            res.send("Unable to retrieve data. Either your key is wrong or the email address is not present in our database.")
        }
    })
});
// this function is responsible for retrieving the data of rsa encrypted data from the database
app.use('/decrypt', function(req, res, next) {
    let stor = new Array();                                       // arrray to store the hybrid encryption data from the database.  hybrid is the name of the table which contains the data encrypted by hybrid encryption

    for(var row in res.hybrid_results) {                          // looping over the results of mmysql query results for hybrid encryption
        for(var column in res.hybrid_results[row]) {              // nested loop because results is a 2d matrix
            stor.push(res.hybrid_results[row][column])           // storing the results for hybrid into stor
        }
    }
 
    db.query('SELECT * FROM rsa WHERE email = ?', res.email_id, function(error, results) {                          // query to retrieve the values of rsa encrypted data from the rsa table
        if(error){
            res.send(error)
        }

        else if(results.length){
            res.rsa_results = results                                                   // storing the results of mysql query for rsa table into res.rsa_results
            res.hybrid_array = stor                                                     // again saving values for res so that next /decrypt can use these values. just using middleware again 
            res.ecdh_key = res.ecdh_key 
            res.rsa_priv_key = res.rsa_priv_key
            res.email_id = res.email_id
            return next();                                                            // calling next /decrypt
        }

        else {
            res.send("Unable to retrieve data. Either your key is wrong or the email address is not present in our database.")
        }
    })
});

// this  /decrypt is responsible for decrypting the data retrieved from rsa and hybrid table from the database
app.use('/decrypt', function(req, res, next) {                                        
    let rsa_array = new Array();                   // array to store the values retrieved from rsa table from the database

    for(var row in res.rsa_results) {             // nested loop because results is a 2d matrix
        for(var column in res.rsa_results[row]) {
            rsa_array.push(res.rsa_results[row][column])                // pushing the values retrieved from the rsa table to rsa_array
        }
    }

    // Decrypting text using RSA
    perf.start();           // start timer for rsa decryption

    const rsa_decrypted_fn = decryption.rsa_decrypt(rsa_array[1], res.rsa_priv_key)
    const rsa_decrypted_ln = decryption.rsa_decrypt(rsa_array[2], res.rsa_priv_key)
    // console.log(rsa_decrypted_fn)
    // console.log(rsa_decrypted_ln)

    var rsa_decrypt_time = perf.stop().time;            // stop timer for rsa decryption



    // Decryption Process for hybrid

    perf.start();              // start timer for hybrid decryption

    // decrypting blowfish text to aes encrypted text
    const blowfish_decrypted_fn = decryption.blowfish_decrypt(res.hybrid_array[1], res.ecdh_key);
    const blowfish_decrypted_ln = decryption.blowfish_decrypt(res.hybrid_array[2], res.ecdh_key);

    
    // decryption from aes encrypted text to plaintext
    const aes_decrypted_fn = decryption.aes_decrypt(blowfish_decrypted_fn, res.hybrid_array[4], res.hybrid_array[5], res.ecdh_key);
    const aes_decrypted_ln = decryption.aes_decrypt(blowfish_decrypted_ln, res.hybrid_array[6], res.hybrid_array[7], res.ecdh_key);

    var hybrid_decrypt_time = perf.stop().time;     // stop timer for hybrid decryption


    res.render("decrypt_success", {rsa_decrypt_time: rsa_decrypt_time,   //rendering encrypt_success.hbs
            rsa_decrypted_fn: rsa_decrypted_fn,
            rsa_decrypted_ln: rsa_decrypted_ln,
            email: res.email_id,
            aes_decrypted_fn: aes_decrypted_fn,
            aes_decrypted_ln: aes_decrypted_ln,
            hybrid_decrypt_time: hybrid_decrypt_time, 
            message: "data is successfully decrypted"
        })


    // console.log(aes_decrypted_fn)
    // console.log(aes_decrypted_ln)
})




app.get("/download", function(req, res) {
    res.zip([
        { path: __dirname + '/rsa_key.txt', name: 'rsa_key.txt' },
        { path: __dirname + '/ecdh_key.txt', name: 'ecdh_key.txt' }
      ]);
    // res.download(__dirname + '/rsa_key.txt',function(error) {
    //     if(error) {
    //         console.log(error)
    //     }
    //     else {
    //         console.log("rsa key successfully donwloaded");
    //     }
    // })
})



const publicDirectory = path.join(__dirname, './public');
app.use(express.static(publicDirectory));

app.set('view engine', 'hbs');

db.connect( (error) => {
    if(error) {
        console.log(error)
    } else {
        console.log("MYSQL Connected ... ");
    }
});

app.get("/", (req, res) => {
    res.render("index");
});

app.listen(5000, () => {
    console.log("Server started on port 5000");
})
