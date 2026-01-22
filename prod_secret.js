Java.perform(function() {
    console.log("\n══════════════════════════════════════════════");
    console.log("  PROD_SECRET CAPTURE");
    console.log("══════════════════════════════════════════════");
     console.log("Wait for the secret to appear below");
    console.log("══════════════════════════════════════════════\n");

    try {
        var RequestBuilder = Java.use("okhttp3.Request$Builder");

        RequestBuilder.addHeader.implementation = function(name, value) {
            if (name === "X-HMAC-ACCESS-KEY") {
                console.log("\nPROD_SECRET = " + value + "\n");
            }
            return this.addHeader(name, value);
        };

        RequestBuilder.header.implementation = function(name, value) {
            if (name === "X-HMAC-ACCESS-KEY") {
                console.log("\nPROD_SECRET = " + value + "\n");
            }
            return this.header(name, value);
        };
    } catch(e) {}
});
