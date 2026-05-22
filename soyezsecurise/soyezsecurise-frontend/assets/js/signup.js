const username = document.getElementById("username")

const masterPassword = document.getElementById("password")

const email = document.getElementById("email")

const signinbtn = document.querySelector(".primary")

const statusmsg = document.getElementById("status-signin")

async function hasher(password){
    
    let passwordbytes = new TextEncoder().encode(password)

    let saltBytes =
    crypto.getRandomValues(
    new Uint8Array(32)
    )
    console.log(saltBytes)
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



document.getElementById("Sign-in").addEventListener(
"submit",
async function(e){
e.preventDefault()  
signinbtn.disabled = true
statusmsg.innerText = ("Wait...")
let usernameV = username.value
let masterpassV = masterPassword.value
let emailV = email.value
statusmsg.innerText = ("deriving keys...")
let result = await hasher(masterpassV)
let argonOutput = result.result.hash


let key = await crypto.subtle.importKey(
    "raw",
    argonOutput,
    "HKDF",
    false,
    ["deriveBits"]
)

let authkey1 = await crypto.subtle.deriveBits(
    {
        name:"HKDF",
        hash:"SHA-256",
        salt: new Uint8Array(32),
        info: new TextEncoder().encode("Authentication/store/list")
    },
    key, 
    256
)





statusmsg.innerText = ("Preparing keys...")

let authkey1bytes = new Uint8Array(authkey1)
let authkey1hex = bytesToHex(authkey1bytes)

let salt = result.saltBytes
salthex = bytesToHex(salt)
let response = await fetch("http://localhost:8000/newuser",
    {
        method:"POST",
        headers:{
            "Content-Type":
            "application/json"
        },
        body:JSON.stringify(
            {
                "username":usernameV,
                "hash": authkey1hex,
                "email": emailV,
                "salt": salthex
            }
        )
    }
)


let data = await response.json()

if(data.ERROR){

    statusmsg.innerText =
    data.ERROR
    signinbtn.disabled = false
}
else if(!response.ok){

    statusmsg.innerText = "Request failed"
    signinbtn.disabled = false
    console.log(data)

    return
}

else{

    statusmsg.innerText = "User Created Successfully"
    localStorage.setItem("username", usernameV)
    localStorage.setItem("authkey",authkey1hex)
    localStorage.setItem("userLoggedIn", "true")
    window.location.href = "enable-otp.html"

}
}
)

