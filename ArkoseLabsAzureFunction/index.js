const axios = require('axios');

module.exports = async function (context, req) {

    // parse Basic Auth username and password
    var header = req.headers["authorization"] || "", // get the header
        token = header.split(/\s+/).pop() || "", // and the encoded auth token
        auth = new Buffer.from(token, "base64").toString(), // convert from base64
        parts = auth.split(/:/), // split on colon
        username = parts[0],
        password = parts[1];

    // Check for HTTP Basic Authentication, return HTTP 401 error if invalid credentials.
    if (
        username !== process.env["BASIC_AUTH_USERNAME"] ||
        password !== process.env["BASIC_AUTH_PASSWORD"]
    ) {
        context.res = {
            status: 401,
        };
        context.log("Invalid Authentication");
        return;
    }

    context.log('JavaScript HTTP trigger function processed a request.');

    let data = req.body;

    const extensionAttributeKey = "extension_" + process.env["B2C_EXTENSIONS_APP_ID"] + "_ArkoseSessionToken";
    let arkoseSessionToken = data && data[extensionAttributeKey]; //extension app-id

    context.log("value of token");
    context.log(arkoseSessionToken);
    
    // Calls Captcha API check for server-side validation of the generated token
    let arkoseVerifyAPI = arkoseSessionToken && await axios.post("https://verify-api.arkoselabs.com/api/v3/verify/", {
        "private_key": process.env["ARKOSE_PRIVATE_KEY"],
        "session_token": arkoseSessionToken,
    }).then(function (response) {
        context.log(response.data);
        const success = response.data.session_is_legit > 0;
        if (!success) {
            context.log("unsuccessful!");
        }
        return success;
    }).catch(function (err) {
        context.log.error("Some other issue with verification API call: " + JSON.stringify(err));
        return false;
    });

    context.log("value of verification check resolution");
    context.log(arkoseVerifyAPI);

    var body = {};
    var status = 200;

    if (!arkoseSessionToken){
        body = {
            "version": "1.0.0",
            "action": "ValidationError",
            "status": 400,
            "userMessage": "Please complete the puzzle so we know you are a real person."
        }
        status = 400;
    } else if (!arkoseVerifyAPI) {
        body = {
            "version": "1.0.0",
            "action": "ShowBlockPage",
            "userMessage": "There was an error with your request. Please try again if you believe this is an error."
        }
    } else {
        body = {
            "version": "1.0.0",
            "action": "Continue",
            [extensionAttributeKey]: "",
        }
    }

    context.res = {
        status: status,
        body: body
    };
};