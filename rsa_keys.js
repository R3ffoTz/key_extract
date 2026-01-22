
Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════════╗");
    console.log("║             RSA Key Hook                         ║");
    console.log("╚══════════════════════════════════════════════════╝\n");

    var Base64 = Java.use("android.util.Base64");

    /**
     * Determine RSA key size from Base64-encoded key
     * X.509 SubjectPublicKeyInfo format lengths:
     * - 1024-bit: ~188 chars base64 (~140 bytes)
     * - 2048-bit: ~392 chars base64 (~294 bytes)
     * - 4096-bit: ~736 chars base64 (~550 bytes)
     */
    function getKeySize(b64String) {
        if (!b64String) return "Unknown";
        
        var len = b64String.replace(/\s/g, '').length;
        
        if (len < 250) return "1024-bit";
        if (len < 500) return "2048-bit";
        if (len < 900) return "4096-bit";
        return "Unknown (" + len + " chars)";
    }

    /**
     * Get key size from byte array length
     */
    function getKeySizeFromBytes(byteLength) {
        if (byteLength < 200) return "1024-bit";
        if (byteLength < 400) return "2048-bit";
        if (byteLength < 700) return "4096-bit";
        return "Unknown (" + byteLength + " bytes)";
    }

    /**
     * Print key information in a nice format
     */
    function printKey(title, algorithm, keySize, b64Key) {
        console.log("\n╔════════════════════════════════════════════════╗");
        console.log("║  " + title.padEnd(44) + "║");
        console.log("╠════════════════════════════════════════════════╣");
        if (algorithm) {
            console.log("║  Algorithm: " + algorithm.padEnd(33) + "║");
        }
        console.log("║  Key Size:  " + keySize.padEnd(33) + "║");
        console.log("╠════════════════════════════════════════════════╣");
        console.log("║  Base64 Key:                                   ║");
        console.log("╚════════════════════════════════════════════════╝");
        console.log(b64Key);
        console.log("─".repeat(50) + "\n");
    }

    // ═══════════════════════════════════════════════════════════════
    // Hook 1: KeyFactory.generatePublic
    // ═══════════════════════════════════════════════════════════════
    try {
        var KeyFactory = Java.use("java.security.KeyFactory");
        
        KeyFactory.generatePublic.implementation = function(keySpec) {
            var result = this.generatePublic(keySpec);
            
            if (result !== null && result !== undefined) {
                try {
                    // Check if methods exist before calling
                    var algorithm = "Unknown";
                    var encoded = null;
                    
                    if (typeof result.getAlgorithm === 'function') {
                        algorithm = result.getAlgorithm();
                    }
                    
                    if (typeof result.getEncoded === 'function') {
                        encoded = result.getEncoded();
                    }
                    
                    if (encoded !== null && encoded !== undefined) {
                        var b64 = Base64.encodeToString(encoded, 2); // NO_WRAP
                        var keySize = getKeySizeFromBytes(encoded.length);
                        printKey("RSA PUBLIC KEY (KeyFactory)", algorithm, keySize, b64);
                    }
                } catch(innerError) {
                    // Silently ignore - not an RSA key we care about
                }
            }
            
            return result;
        };
        console.log("[✓] KeyFactory.generatePublic hook installed");
    } catch(e) {
        console.log("[✗] KeyFactory hook failed: " + e.message);
    }

    // ═══════════════════════════════════════════════════════════════
    // Hook 2: X509EncodedKeySpec constructor
    // ═══════════════════════════════════════════════════════════════
    try {
        var X509EncodedKeySpec = Java.use("java.security.spec.X509EncodedKeySpec");
        
        X509EncodedKeySpec.$init.overload("[B").implementation = function(encoded) {
            if (encoded !== null && encoded !== undefined && encoded.length > 100) {
                try {
                    var b64 = Base64.encodeToString(encoded, 2);
                    var keySize = getKeySizeFromBytes(encoded.length);
                    printKey("X509 KEY SPEC (Raw)", "RSA", keySize, b64);
                } catch(innerError) {
                    // Silently ignore
                }
            }
            
            return this.$init(encoded);
        };
        console.log("[✓] X509EncodedKeySpec hook installed");
    } catch(e) {
        console.log("[✗] X509EncodedKeySpec hook failed: " + e.message);
    }

    // ═══════════════════════════════════════════════════════════════
    // Hook 3: Base64.decode for RSA keys
    // ═══════════════════════════════════════════════════════════════
    try {
        Base64.decode.overload("java.lang.String", "int").implementation = function(str, flags) {
            // RSA public keys in X.509 format start with "MII"
            if (str !== null && str !== undefined) {
                var trimmed = str.trim();
                if (trimmed.length > 150 && trimmed.substring(0, 3) === "MII") {
                    var keySize = getKeySize(trimmed);
                    printKey("RSA KEY (Base64 Decode)", "RSA", keySize, trimmed);
                }
            }
            
            return this.decode(str, flags);
        };
        console.log("[✓] Base64.decode hook installed");
    } catch(e) {
        console.log("[✗] Base64 hook failed: " + e.message);
    }

    // ═══════════════════════════════════════════════════════════════
    // Hook 4: RSAPublicKeySpec (alternative key creation)
    // ═══════════════════════════════════════════════════════════════
    try {
        var RSAPublicKeySpec = Java.use("java.security.spec.RSAPublicKeySpec");
        
        RSAPublicKeySpec.$init.overload("java.math.BigInteger", "java.math.BigInteger").implementation = function(modulus, exponent) {
            if (modulus !== null) {
                try {
                    var bitLength = modulus.bitLength();
                    var keySize = bitLength + "-bit";
                    console.log("\n╔════════════════════════════════════════════════╗");
                    console.log("║  RSA KEY SPEC (Modulus/Exponent)               ║");
                    console.log("╠════════════════════════════════════════════════╣");
                    console.log("║  Key Size:  " + keySize.padEnd(33) + "║");
                    console.log("║  Exponent:  " + exponent.toString().padEnd(33) + "║");
                    console.log("╚════════════════════════════════════════════════╝");
                    console.log("Modulus (hex): " + modulus.toString(16).substring(0, 64) + "...");
                    console.log("─".repeat(50) + "\n");
                } catch(innerError) {
                    // Silently ignore
                }
            }
            
            return this.$init(modulus, exponent);
        };
        console.log("[✓] RSAPublicKeySpec hook installed");
    } catch(e) {
        console.log("[✗] RSAPublicKeySpec hook failed: " + e.message);
    }

    console.log("\n[*] All hooks ready - LOGIN to the app to capture RSA keys\n");
});
