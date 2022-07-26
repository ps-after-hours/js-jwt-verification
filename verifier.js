const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const axios = require('axios');

/*
 * Use this tool to generate test tokens and JWK https://www.scottbrady91.com/tools/jwt
 */
const jwk = {
    "alg": "RS256",
    "e": "AQAB",
    "key_ops": [
      "verify"
    ],
    "kty": "RSA",
    "n": "tGOiczNG_qXJTjzQtWNHVl54oHQS0CaPgFeQCEJ_oRe4jCX2mCuxF86-rGpphBenFG3ykoBIor1ngvvg3a1QkkbhtDOnLsc864KsvFceRv8TuHGuxhebE4s4zrzs49ZlLMEE26ZDR_BL8oxspuYa_61nBylojA7jZU4S8iDKhyFRw-c4rXBcu3xwH9oeH6PjbYrdKzgCE5CVS0tnXG7Ba2W03xoVKQ-aOQ_v_7HIZoiBGjqR1AH1k-JbGo84UceYCWyBFDTnwLSZAA1vjL49_U31RZF2azfRgfJZXa6zAHbnd682MDNP9co6XnXCxXehp6hq8QaJtN2xT5-5Jal6t2cBSz9WxRRNJz_Cs_E7UXmd3LBV6AJPMbCq5rH1ASSXXGJIc7VBVKd4_T5x5WVl8s0A8NAy7KDJR1y3WZuh2oFdO45gWGcmCJarBH1bpZiwAymZlTxuCkQAzmaXUE-UOyqst8buiB_JQhIpTFSGVtHSouO-Ebk5t6BbtbV3aRmx",
    "use": "sig",
    "kid": "8df7da8af0196bbc400ac10ab2854bad"
  };

const incomingToken = "eyfgsdfsghgfdsJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjhkZjdkYThhZjAxOTZiYmM0MDBhYzEwYWIyODU0YmFkIn0.eyJpc3MiOiJodHRwczovL2lkcC5sb2NhbCIsImF1ZCI6Im15X2NsaWVudF9hcHAiLCJzdWIiOiI1YmU4NjM1OTA3M2M0MzRiYWQyZGEzOTMyMjIyZGFiZSIsImV4cCI6MTY1ODgyODQ5MSwiaWF0IjoxNjU4ODI4MTkxfQ.bj9yyhK_2M3Ok42lX3mw4D1wGZo4oVl5-zqAT6B1PmE_QDrffclrZm0jnr6QPrQ1PDABkFKVVfh39KvdtxA_MZ2B9XcLI-tTlS06e0ti_C8QhibowZ_sxb9XsTwWuTyBpY9_Opl8zWCaLP3VmPPIHZ6_65AZqMjvkI275OrzHMJ5GNgk4DBLxE2hDP9tybZCqCIf-PLC2wVOB55NQ_K4xCwy6XFsJW7X35ZHQTq3dpSJ2Z_Tiba9_JDrGNgF_f-6btf3J3EWxgxZ4eQtD-8qRIEGw2CqhgfP6ahVoILzsH5Bn47GRjZ-geX06pQoHA7whTbAlUF2P2s0flR78M_Pqx-96WuZrshlygvHNMwbwWXPn32Ka_lovljMcFTwgRWSGUQDdNjF6IaAm0MLZXrajiCEHqcCaWuYgqiNpOXA-BwNd3_lXzmrRWarVt2P2CdoqqoM_GJ1U6XqX2jS5O4gO15xZ1Byt-9hRBMfdcDtvuc9y3wGYVJt6PpCqbpHqCDf"

const mockedResponse = {
    data: {
        keys: [jwk]
    }
}

const trustedIssuers = [
    "https://idp.local"
];

function getJwkByKid(url, kid) {
    let issResponse;
  
    //Mock the response for the issuer
    // this matches the Keycloak url for the Keycloak's JWK
    // issResponse = await axios(iss);
    issResponse = mockedResponse;
  
    for (let index = 0; index < issResponse.data.keys.length; index++) {
        const key = issResponse.data.keys[index];
        if (key.kid === kid) {
          return key;
        }
      }
    
      throw new Error('Failed to find JWK by token KID');
}

/**
 * This method verifies the token and returns the user id. If token is invalid, it throws an error.
 * If token is valid, it returns the decoded token.
 * @param {*} token 
 */
function verify(token) {
    const decodedToken = jwt.decode(token, { complete: true });

    // If token is not valid (syntax error), throw an error and finish proessing
    if (!decodedToken) {
        throw new Error('Token decode failed, syntax error');
    }

    //Verify if token issuer is trusted
    if (!trustedIssuers.includes(decodedToken.payload.iss)) {
        throw new Error('The token issuer is not trusted');
    }

    const url = decodedToken.payload.iss + "/protocol/openid-connect/certs";

    //Verify if token is not expired and signature match
    jwt.verify(token, jwkToPem(getJwkByKid(url, decodedToken.header.kid)));

    return decodedToken;
}

const verifiedToken = verify(incomingToken);

if (verifiedToken) {
    console.log("Token is valid");
}

console.log(verifiedToken.payload);