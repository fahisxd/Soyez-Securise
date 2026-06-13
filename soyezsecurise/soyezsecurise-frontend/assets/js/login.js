const login_username = document.getElementById("login-username")

const login_masterPassword = document.getElementById("login-password")

const loginbtn = document.querySelector(".primary")

const login_statusmsg = document.getElementById("status-login")

const login_otp = document.getElementById("otp")

async function login_hasher(password, salt){
    let saltBytes = Uint8Array.from(salt.match(/.{1,2}/g).map(b=>parseInt(b,16)))
    let passwordbytes = new TextEncoder().encode(password)
    let result = await argon2.hash({

    pass:passwordbytes,

    salt:saltBytes,

    time:4,

    mem:65536,

    parallelism:4,

    hashLen:32,

    type:
    argon2.ArgonType.Argon2id

    })

    return {
        result,
        saltBytes
    }

}

function bytesToHex(bytes){
    return Array.from(bytes).map(
        byte =>
        byte.toString(16)
        .padStart(2,"0")
    ).join("")
}

async function generatesign(noncehex, keyhex){
    let noncebytes = Uint8Array.from(noncehex.match(/.{1,2}/g).map(b => parseInt(b,16)))
    let keybytes =  new Uint8Array(keyhex)
    let cryptoKey = await crypto.subtle.importKey( "raw", keybytes, { name:"HMAC", hash:"SHA-256" }, false, ["sign"] ) 
    let signaturebytes = await crypto.subtle.sign( "HMAC", cryptoKey, noncebytes ) 
    let signaturearray = new Uint8Array(signaturebytes) 
    let signature = bytesToHex(signaturearray) 
    return signature
}

document.getElementById("Login").addEventListener(
"submit",
async function(e){
e.preventDefault()  
loginbtn.disabled = true
login_statusmsg.innerText = ("Wait...")
let usernameV = login_username.value
let masterpassV = login_masterPassword.value
let otpV = login_otp.value
if(otpV == ""){
    let otpV = 0
}
login_statusmsg.innerText = "Requesting server for username"

let response = await fetch(`${server_link}/login`,
    {
        method:"POST",
        headers:{
            "Content-Type":
            "application/json"
        },
        body:JSON.stringify({
            "username": usernameV
        })

    }

)

let data = await response.json()

if(data.ERROR){

    login_statusmsg.innerText = data.ERROR
    loginbtn.disabled = false
}

else if(!response.ok){
    login_statusmsg.innerText = "Request failed"
    loginbtn.disabled = false
    return
}

else{
    login_statusmsg.innerText = "Generating Signature"
    let nonce = data.nonce
    let requestid = data.request_id
    let salt = data.salt

    let result = await login_hasher(masterpassV, salt)
    let argonOutput = result.result.hash
    let key = await crypto.subtle.importKey(
    "raw",
    argonOutput,
    "HKDF",
    false,
    ["deriveBits"]
)
    let login_authkey1 = await crypto.subtle.deriveBits(
    {
        name:"HKDF",
        hash:"SHA-256",
        salt: new Uint8Array(32),
        info: new TextEncoder().encode("Authentication/store/list")
    },
    key, 
    256
)

    window.vaultkey = await crypto.subtle.deriveBits(
    {
        name:"HKDF",
        hash:"SHA-256",
        salt: new Uint8Array(32),
        info: new TextEncoder().encode("EnCryPtiONKeY")
    },
    key, 
    256
    
)
let signature = await generatesign(nonce, login_authkey1)
login_statusmsg.innerText = "Signature Generated"
login_statusmsg.innerText = "Requesting Server"

let verifyResponse = await fetch(`${server_link}/login2`,
    {
    method:"POST",

    headers:{
        "Content-Type":
        "application/json"
    },
    body:JSON.stringify({
        "signature": signature,
        "username": usernameV,
        "otp": otpV,
        "request_id": requestid
    })
})
let verifyData = await verifyResponse.json()



if(verifyData.ERROR){
    login_statusmsg.innerText = verifyData.ERROR
}
else if(!verifyResponse.ok){
    login_statusmsg.innerText = "Request failed"
    loginbtn.disabled = false
    return
}
else{
    login_statusmsg.innerText = "Logged in succesfully"
    localStorage.setItem("username", usernameV)
    localStorage.setItem("authkey",bytesToHex(new Uint8Array(login_authkey1)))
    localStorage.setItem("userLoggedIn", "true")
    window.location.href = "#"
}
}
}
)
