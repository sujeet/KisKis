"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF;
var HMAC = lib.HMAC;
var SHA256 = lib.SHA256;
var setup_cipher = lib.setup_cipher;
var enc_gcm = lib.enc_gcm;
var dec_gcm = lib.dec_gcm;
var bitarray_slice = lib.bitarray_slice;
var bitarray_to_string = lib.bitarray_to_string;
var string_to_bitarray = lib.string_to_bitarray;
var bitarray_to_hex = lib.bitarray_to_hex;
var hex_to_bitarray = lib.hex_to_bitarray;
var bitarray_to_base64 = lib.bitarray_to_base64;
var base64_to_bitarray = lib.base64_to_bitarray;
var byte_array_to_hex = lib.byte_array_to_hex;
var hex_to_byte_array = lib.hex_to_byte_array;
var string_to_padded_byte_array = lib.string_to_padded_byte_array;
var string_to_padded_bitarray = lib.string_to_padded_bitarray;
var string_from_padded_byte_array = lib.string_from_padded_byte_array;
var string_from_padded_bitarray = lib.string_from_padded_bitarray;
var random_bitarray = lib.random_bitarray;
var bitarray_equal = lib.bitarray_equal;
var bitarray_len = lib.bitarray_len;
var bitarray_concat = lib.bitarray_concat;
var dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
    // Class-private instance variables.
    var priv = {
        secrets: {
            k: 0,
            key_domain: 0,
            key_record: 0,
            key_data: 0
        },
        data: { 
            kvs : {},
            counter : 0
        }
    };

    // Maximum length of each password in bytes.
    var MAX_PW_LEN_BYTES = 64;
    
    // Flag to indicate whether password manager is "ready" or not
    var ready = false;

    var keychain = {};
    
    // Are we just storing a count or an hash in trusted data storage?
    keychain.JUST_STORE_COUNT = false; // set to true to check extra credit
                                       // portion.
    
    // Takes a password of length 64 or less.
    // Returns a string of exactly 65 length.
    // The last byte has the length of the original password encoded in ASCII.
    // First those many bytes are the password itself.
    // Example:
    // Password        : "sujeet"
    // Padded password : "sujeet<58 characters of no concern><chr6>"
    // Where <chr6> denotes the ascii character with value 6.
    keychain.pad_password = function (password) {
        var original_length = password.length;
        for (var i = password.length;
             i < MAX_PW_LEN_BYTES;
             i++) {
            password += "_";
        }
        return password + String.fromCharCode (original_length);
    };
    
    keychain.strip_password = function (padded_password) {
        return padded_password.slice (
            0,
            padded_password.charCodeAt (MAX_PW_LEN_BYTES)
        );
    };
    
    // Master key to generate other keys.
    // Other keys are generated using HMAC.
    // HMAC is a PRP, so the generated keys are
    // random too. (indistinguishable from random)
    // We need a 256 bit key for that.
    keychain.get_master_key = function (password) {
        return KDF (password, "master key");
    };

    keychain.get_domain_hmac_key = function (master_key) {
        // 256 bit key for HMAC
        return HMAC (
            master_key,
            string_to_bitarray("hmac the domain")
        );
    };
    
    keychain.get_enc_key = function (master_key, unique_string) {
        // returns SJCL's internal cipher data structure
        // to be used with GCM
        return setup_cipher (
            bitarray_slice (
                HMAC (
                    master_key,
                    string_to_bitarray (unique_string)
                ),
                0,
                128
            )
        ); 
    };
    
    keychain.get_record_enc_key = function (master_key) {
        return keychain.get_enc_key (master_key, "encrypt record");
    };
    
    keychain.get_data_enc_key = function (master_key) {
        return keychain.get_enc_key (master_key, "encrypt keychain");
    };

    keychain.init_keys = function (password) {
        priv.secrets.key_master = keychain.get_master_key (password);
        
        priv.secrets.key_domain = keychain.get_domain_hmac_key (
            priv.secrets.key_master
        );

        priv.secrets.key_record = keychain.get_record_enc_key (
            priv.secrets.key_master
        );

        priv.secrets.key_data = keychain.get_data_enc_key (
            priv.secrets.key_master
        );
    };

    /** 
     * Creates an empty keychain with the given password. Once init is called,
     * the password manager should be in a ready state.
     *
     * Arguments:
     *   password: string
     * Return Type: void
     */
    keychain.init = function (password) {
        priv.data.version = "CS 255 Password Manager v1.0";
        keychain.init_keys (password);
        ready = true;
    };

    /**
     * Loads the keychain state from the provided representation (repr). The
     * repr variable will contain a JSON encoded serialization of the contents
     * of the KEYCHAIN (as returned by the save function).
     * The trusted_data_check is an *optional* SHA-256 checksum
     * that can be used to validate the 
     * integrity of the contents of the KEYCHAIN.
     * 
     * If the checksum is provided and the integrity check fails,
     * an exception should be thrown. 
     * 
     * You can assume that the representation passed to load is well-formed 
     * (e.g., the result of a call to the save function). Returns true if
     * the data is successfully loaded and the provided password is correct.
     * Returns false otherwise.
     *
     * Arguments:
     *   password:           string
     *   repr:               string
     *   trusted_data_check: string
     * Return Type: boolean
     */
    keychain.load = function (password, repr, trusted_data_check) {
        var master_key_derived = keychain.get_master_key (password);
        var data_key_derived = keychain.get_data_enc_key (
            master_key_derived
        );
        var encrypted_data = JSON.parse (repr).encrypted_data;
        var data_json;

        //Check if master password is valid
        try {
            data_json = bitarray_to_string (
                dec_gcm (data_key_derived, encrypted_data)
            );
        }
        catch (e) {
            return false;
        }
        
        priv.data = JSON.parse (data_json);

        if (trusted_data_check !== undefined) {
            // Extra credit : trusted_data_check is just a number.
            if (typeof trusted_data_check == "number") {
                if (trusted_data_check != priv.data.counter) {
                    console.log (trusted_data_check, priv.data.counter);
                    throw "Keychain has been tampered with";
                }
            }
            // trusted_data_check is the SHA256 check.
            else {
                var check_tag = SHA256 (encrypted_data);
                if (! bitarray_equal (trusted_data_check, check_tag)) {
                    throw "Keychain has been tampered with";
                }
            }
        }

        keychain.init (password);
        return true;    
    };

    /**
     * Returns a JSON serialization of the contents of the keychain that can
     * be loaded back using the load function. The return value should
     * consist of an array of two strings:
     *   arr[0] = JSON encoding of password manager
     *   arr[1] = SHA-256 checksum
     * As discussed in the handout, the first element of the array should
     * contain all of the data in the password manager. The second element
     * is a SHA-256 checksum computed over the password manager to preserve
     * integrity.
     *
     * If the password manager is not in a ready-state, return null.
     *
     * Return Type: array
     */ 
    keychain.dump = function() {
        if (!ready) return null;

        priv.data.counter += 1;
        var data_string = JSON.stringify (priv.data);
        var encrypted_data = enc_gcm (priv.secrets.key_data,
                                      string_to_bitarray (data_string));
        
        if (keychain.JUST_STORE_COUNT) {
            // Extra credit portion.
            return [JSON.stringify ({encrypted_data:encrypted_data}),
                    priv.data.counter];
            
        }
        else {
            var hash = SHA256 (encrypted_data);
            return [JSON.stringify ({encrypted_data:encrypted_data}),
                    hash];
        }
    };

    /**
     * Fetches the data (as a string)
     * corresponding to the given domain from the keychain.
     * For a swap attack, the adversary must produce a
     * (domain_name + password), Tag pair. 
     * 
     * If there is no entry in the keychain that matches the given domain,
     * then return null.
     * 
     * If the password manager is not in a ready state, throw an exception.
     * 
     * If tampering has been detected with the records, throw an exception.
     *
     * Arguments:
     *   domain_name: string
     * Return Type: string
     */
    keychain.get = function (domain_name) {
        if (!ready) throw "Not ready";

        var domain_hmac = HMAC (priv.secrets.key_domain, domain_name);
        
        if (! (domain_hmac in priv.data.kvs)) return null;

        var record;
        try {
            record = bitarray_to_string (
                dec_gcm (priv.secrets.key_record,
                         priv.data.kvs [domain_hmac])
            );
        }
        catch (e) {
            throw "Encrypted password for " + domain_name + " tampered.";
        }
        
        // Check for a swap attack.
        var original_domain = record.slice (0,
                                            record.length
                                            - MAX_PW_LEN_BYTES
                                            - 1);
        if (original_domain != domain_name) {
            throw "Detected a swap attack for " + domain_name;
        }
        
        // Now we are sure that there was no tampering,
        // And no swap attack too.

        // We have encrypted domain_name||padded_password
        var padded_password =
            record
            .slice (domain_name.length,
                    domain_name.length + MAX_PW_LEN_BYTES + 1);
        
        return keychain.strip_password (padded_password);
    };

    /** 
     * Inserts the domain and associated data into the Keychain.
     * If the domain is already in the password manager,
     * this method should update its value.
     * If not, create a new entry in the password manager.
     * If the password manager is not in a ready state, throw an exception.
     *
     * Arguments:
     *   domain_name: string
     *   password: string
     * Return Type: void
     */
    keychain.set = function (domain_name, password) {
        if (!ready) throw "Not ready";

        var padded_password = keychain.pad_password (password);
        var domain_hmac = HMAC (priv.secrets.key_domain, domain_name);
        var encrypted_value = enc_gcm (
            priv.secrets.key_record,
            string_to_bitarray (domain_name + padded_password)
        );
        priv.data.kvs [domain_hmac] = encrypted_value;
    };

    /**
     * Removes the record with name from the password manager.
     * Returns
     * true if the record with the specified name is removed,
     * false otherwise.
     * 
     * The password manager is not in a ready state, throws an exception.
     *
     * Arguments:
     *   name: string
     * Return Type: boolean
     */
    keychain.remove = function (domain_name) {
        if (!ready) throw "Not ready";
        var domain_hmac = HMAC (priv.secrets.key_domain, domain_name);
        if (domain_hmac in priv.data.kvs) {
            delete priv.data.kvs [domain_hmac];
            return true;
        }
        else {
            return false;
        }
    };

    return keychain;
};

module.exports.keychain = keychain;
