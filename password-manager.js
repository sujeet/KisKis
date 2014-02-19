"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
      secrets: {k: 0,
                k1: 0,
                k2: 0,
                k3: 0,
                k4: 0},
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    priv.data.version = "CS 255 Password Manager v1.0";
    ready = true;
    priv.secrets.k = KDF(password, "0");
    priv.secrets.k1 = HMAC(priv.secrets.k, string_to_bitarray("aparna"));   //For HMACS of domains
    priv.secrets.k2 = HMAC(priv.secrets.k, string_to_bitarray("sujeet"));  //For MAC of passwords
    priv.secrets.k3 = HMAC(priv.secrets.k, string_to_bitarray("crypto"));  //For final encryption
    priv.secrets.k4 = HMAC(priv.secrets.k, string_to_bitarray("stanford"));
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trusted_data_check) {
    var k_derived = KDF(password, "0");
    var k2_derived = HMAC(k_derived, "crypto");
    var ciphertext_structure = setup_cipher(bitarray_slice(k2_derived, 0, 128));
    var encrypted_kvs = JSON.parse(repr);
    var kvs;

    //Check if master password is valid
    try {
        kvs = dec_gcm(ciphertext_structure, encrypted_kvs);
    }
    catch(e) {
        throw "Incorrect Password";
        return false;
    }
    //Check for integrity
    var check_tag = SHA256(kvs);
    if(bitarray_to_string(check_tag) != trusted_data_check) {
        throw "KVS has been tampered with";
        return false;
    }

    keychain = JSON.parse(kvs);
    return true;    
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
    var arr = new Array();
    var kvs_string = JSON.stringify(keychain);
    var ciphertext_structure = setup_cipher(bitarray_slice(priv.secrets.k3, 0, 128));
    var encrypted_kvs = enc_gcm(ciphertext_structure, string_to_bitarray(kvs_string));
    var check_tag = SHA256(encrypted_kvs);
    arr[0] = JSON.stringify(encrypted_kvs);
    arr[1] = check_tag;

    return arr

  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if(!ready)
        throw "Not ready";

    var domain = HMAC(priv.secrets.k1, name);
    if(domain in keychain) {
        var encrypted_password = keychain[domain];
        var ciphertext_structure = setup_cipher(bitarray_slice(priv.secrets.k2, 0, 128));
        try {
            var password = dec_gcm(ciphertext_structure, encrypted_password);
            return bitarray_to_string(password);
        } catch(e) {
            throw "Password has been tampered with";
        }
    }
    else
        return null;
  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
      if(!ready)
          throw "Not ready";
      var domain = HMAC(priv.secrets.k1, name);
      var ciphertext_structure1 = setup_cipher(bitarray_slice(priv.secrets.k2, 0, 128));
      var encrypted_password = enc_gcm(ciphertext_structure1, string_to_bitarray(value));
      var domain_password = bitarray_concat(domain, encrypted_password);
      var ciphertext_structure2 = setup_cipher(bitarray_slice(priv.secrets.k4, 0, 128));
      //var tag = enc_gcm(ciphertext_structure2, domain_password);
      keychain[domain] = encrypted_password;
      //keychain[domain] = bitarray_concat(encrypted_password,tag);
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
      if(!ready)
          throw "Not ready";
      var domain = HMAC(priv.secrets.k1, name);
      if(domain in keychain) {
          delete keychain[domain];
          return true;
      }
      else
          return false;
      }

  return keychain;
}

module.exports.keychain = keychain;
