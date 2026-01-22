Java.perform(function() {
    console.log("\n");
    console.log("╔════════════════════════════════════════════════════════════════════════════╗");
    console.log("║                            KEY CAPTURE SCRIPT                              ║");
    console.log("╚════════════════════════════════════════════════════════════════════════════╝\n");
    console.log("  Instructions:");
    console.log("    1. Logout from the app");
    console.log("    2. Login again");
    console.log("\n  Results will appear automatically in 30 seconds...");
    console.log("  Or call: rpc.exports.summary()\n");

    var Base64 = Java.use("android.util.Base64");
    
    var found = {
        hmacSecretKey: null,
        prodSecret: null,
        vinKey: null,
        vinIV: null,
        rsaPublicKey: null
    };

    // 1. Secret Keys (SecretKeySpec)
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(keyBytes, algorithm) {
            var utf8 = "";
            for (var i = 0; i < keyBytes.length; i++) {
                var c = keyBytes[i] & 0xFF;
                utf8 += (c >= 32 && c <= 126) ? String.fromCharCode(c) : "";
            }

            if ((algorithm === "HmacSHA256" || algorithm === "HMACSHA256") && keyBytes.length === 40) {
                found.hmacSecretKey = utf8;
            } else if ((algorithm === "HmacSHA256" || algorithm === "HMACSHA256") && keyBytes.length === 32) {
                found.prodSecret = utf8;
            } else if (algorithm === "AES" && keyBytes.length === 16) {
                found.vinKey = utf8;
            }

            return this.$init(keyBytes, algorithm);
        };
    } catch(e) {}

    // 2. IV Parameter (IvParameterSpec)
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

        IvParameterSpec.$init.overload("[B").implementation = function(ivBytes) {
            var utf8 = "";
            for (var i = 0; i < ivBytes.length; i++) {
                var c = ivBytes[i] & 0xFF;
                utf8 += (c >= 32 && c <= 126) ? String.fromCharCode(c) : "";
            }

            if (ivBytes.length === 8 || ivBytes.length === 16) {
                found.vinIV = utf8;
            }

            return this.$init(ivBytes);
        };
    } catch(e) {}

    // 3. RSA Public Key (KeyFactory)
    try {
        var KeyFactory = Java.use("java.security.KeyFactory");

        KeyFactory.generatePublic.implementation = function(keySpec) {
            var result = this.generatePublic(keySpec);
            
            try {
                var encoded = result.getEncoded();
                if (encoded && encoded.length > 0) {
                    var b64 = Base64.encodeToString(encoded, 2).replace(/\n/g, "");
                    
                    if (b64.startsWith("MIG")) {
                        found.rsaPublicKey = b64;
                    }
                }
            } catch(e) {}
            
            return result;
        };
    } catch(e) {}

    // 4. Alternative RSA capture via X509EncodedKeySpec
    try {
        var X509EncodedKeySpec = Java.use("java.security.spec.X509EncodedKeySpec");

        X509EncodedKeySpec.$init.overload("[B").implementation = function(encodedKey) {
            try {
                if (encodedKey && encodedKey.length > 100) {
                    var b64 = Base64.encodeToString(encodedKey, 2).replace(/\n/g, "");
                    
                    if (b64.startsWith("MIG")) {
                        found.rsaPublicKey = b64;
                    }
                }
            } catch(e) {}
            
            return this.$init(encodedKey);
        };
    } catch(e) {}

    // Summary function
    function printSummary() {
        var keysFound = 0;
        if (found.hmacSecretKey) keysFound++;
        if (found.prodSecret) keysFound++;
        if (found.vinKey) keysFound++;
        if (found.vinIV) keysFound++;
        if (found.rsaPublicKey) keysFound++;

        console.log("\n");
        console.log("╔════════════════════════════════════════════════════════════════════════════╗");
        console.log("║                        CAPTURED KEYS (" + keysFound + "/5)                               ║");
        console.log("╚════════════════════════════════════════════════════════════════════════════╝\n");
        
        console.log("HMAC_SECRET_KEY     = " + (found.hmacSecretKey || "NOT FOUND"));
        console.log("PROD_SECRET         = " + (found.prodSecret || "NOT FOUND"));
        console.log("VIN_KEY             = " + (found.vinKey || "NOT FOUND"));
        console.log("VIN_IV              = " + (found.vinIV || "NOT FOUND"));
        console.log("PASSWORD_PUBLIC_KEY = " + (found.rsaPublicKey || "NOT FOUND"));
        
        if (keysFound === 5) {
            console.log("\n✓ All keys captured successfully!\n");
        } else {
            console.log("\n⚠ Missing keys - try using the app more, then call rpc.exports.summary()\n");
        }
    }

    // Export functions for interactive use
    rpc.exports = {
        summary: printSummary,
        keys: function() { return found; }
    };

    // Auto-summary after 30 seconds
    setTimeout(function() {
        printSummary();
    }, 30000);
});
