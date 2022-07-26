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
    "n": "txICBhuqPJ709Hyg-tvpYNWFJ7h96_awNgcj-NRPS9UF2OtGj13B-dqIHAHZZKtg3P9i7W4dwvTdfwhj3B1DevwufXGHDfj-Y4bA4JSbkdHz7Yi1xsCaiWXdWA1B-_vPByMD655zZTNF-fxvc7EqY82UnZk0U0-kOK-fj_dg1244NuZRy8djHL97ivbvfKkDyju-PDzo2mkRB3aMOoYdLgEnbIzVBpkaNvmqKw-PDuX7O9R6CIvzlPt8R50F5cn1YfgdwVxelHTJ5CiXsGIqmq7MEJu0hJ5IMfMSpU75jwQ9benDiFbXny0jqZ9tMhCiX1ncKY7xjJES28vIIcu_cF6pu9S0iUs66ldf1szxZdR8UF0aCgftUKX4G-gn4g7J44Q2pn33fCNN0xOgBWqYYinUB54udggJPjoihV7eGKrhCnunWmM_bZNAapsYUlKoPnk9B4pleHyJs-3kzZ9MqfGfZZc1lSjOm-I2JkWmMG2H9Bamuk4J949ecgrVkfIl",
    "use": "sig",
    "kid": "45b56dae216773306705f884311b87eb"
  };

const incomingToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjQ1YjU2ZGFlMjE2NzczMzA2NzA1Zjg4NDMxMWI4N2ViIn0.eyJpc3MiOiJodHRwczovL2lkcC5sb2NhbCIsImF1ZCI6Im15X2NsaWVudF9hcHAiLCJzdWIiOiI1YmU4NjM1OTA3M2M0MzRiYWQyZGEzOTMyMjIyZGFiZSIsImV4cCI6MTY1ODgyMTcyMCwiaWF0IjoxNjU4ODIxNDIwfQ.B1LrglWMLsztJw-Nw1stgP1SQEgRYYyfV9K4HB7vsa_etpSvaYZ77VlucxmyyyMoCxaNVSx4f6NWD-QkkxGSdW1NWQ0fYJI2tcOPwSQ2eDYQJV0VKaDX4sHRLDjE7eujGCNv3yBwr0hF-LDhhbElET_wiKVfU_wsei5Qg6TAot_8QsqPEpkUSaa_KcJbRa5AYcCGgJ7NzkfXQC5RMw1NQz7mUhSckU-KIu6LicuNmrJSR11C3pbk5M6_yX6tvoMASAUbrIxvwAP3lOURhqH3ppx2YjgSMk4QvoVdGC1DqFMYfdv9pVaWLvv5AlG4FKdmNn04Rffx__HXNMpB8rKJpMxDE-IFU_pW5mBdJiMkbQZ1BmYswK6yct0crI-IDg4RVOy2XtW0l25TTE6lK3R12l9S9YhoaRAsqyNz3Z4mqJ2C-wfgKfaFPOvLAH4UdPJeg70Pe6yrOrH-bpCgNpGDTSFI0pdJEsth2h6HjjUFUQvU0dOJlgQ3bpIG4xiCU7-Q"

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