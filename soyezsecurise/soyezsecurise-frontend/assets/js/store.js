const usernametobestored = document.getElementById("usernametobestored")

const storeservicename = document.getElementById("store-service-name")

const passwordtobestored = document.querySelector("#StorePassword input[name='password']")

const storepasswordfunc = document.getElementById("storepassword")

const store_status = document.getElementById("status-store")

function bytesToHex(bytes){
    return Array.from(bytes).map(
        byte =>
        byte.toString(16)
        .padStart(2,"0")
    ).join("")
}

function base64ToBytes(base64){

    base64 = base64.trim()

    let binary = window.atob(base64)

    let bytes = new Uint8Array(binary.length)

    for(let i=0;i<binary.length;i++){
        bytes[i] = binary.charCodeAt(i)
    }

    return bytes
}

async function storegeneratesign(noncehex, keyhex){
    let noncebytes = Uint8Array.from(noncehex.match(/.{1,2}/g).map(b => parseInt(b,16)))
    let keybytes = Uint8Array.from(keyhex.match(/.{1,2}/g).map(b=>parseInt(b,16)))

    let cryptoKey = await crypto.subtle.importKey(
        "raw",
        keybytes,
        {
            name:"HMAC",

            hash:"SHA-256"
        },
         false,

        ["sign"]

    )
    let signaturebytes = await crypto.subtle.sign(
        "HMAC",
        cryptoKey,
        noncebytes
    )
    let signaturearray = new Uint8Array(signaturebytes)
    let signature = bytesToHex(signaturearray)
    return signature
}



document.getElementById("storepassword").addEventListener("click",
async function(e){
    e.preventDefault() 
    if(window.vaultkey){
        storepasswordfunc.href = "#store-password"
        window.location.href = "#store-password"
    }
    else{
        storepasswordfunc.href = "#login"
        window.location.href = "#login"
    }
})

document.getElementById("StorePassword").addEventListener("submit",
async function(e){
    e.preventDefault()
    store_status.innerText = "Encrypting..."
    let usernameS = usernametobestored.value
    let service_nameV = storeservicename.value
    let usernameV = localStorage.getItem("username")
    const passwordValue = passwordtobestored.value
    let keybytes = window.vaultkey
    let iv = crypto.getRandomValues(new Uint8Array(12))
    let key = await crypto.subtle.importKey(
        "raw",
        keybytes,
        {
            name:"AES-GCM"
        },
        false,
        ["encrypt"]

    )
    let encrypted = await crypto.subtle.encrypt(
        {
            name:"AES-GCM",

            iv:iv

        },
        key,
        new TextEncoder().encode(passwordValue)
    )

    let payload = new Uint8Array(iv.length + encrypted.byteLength)
    payload.set(iv)
    payload.set(new Uint8Array(encrypted),iv.length)
    const final = btoa(String.fromCharCode(...payload))
    store_status.innerText = "Requesting server for username"

    let response = await fetch(`${server_link}/storepassword`,
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

        store_status.innerText = data.ERROR
        return
    }

    else if(!response.ok){
        store_status.innerText = "The server could not start this request. Please try again."
        return
    }

    else{
        store_status.innerText = "Verifying"
        let authkey =  localStorage.getItem("authkey")
        
        store_status.innerText = "Generating Signature"
        let nonce = data.nonce
        let requestid = data.request_id
        let enc_data = final


        let signature = await storegeneratesign(nonce, authkey)
        store_status.innerText = "Requesting server"
        let verifyResponse = await fetch(`${server_link}/storepassword2`,
        {
        method:"POST",

        headers:{
            "Content-Type":
            "application/json"
        },
        body:JSON.stringify({
                "signature": signature,
                "username": usernameV,
                "password_name": service_nameV,
                "usernametbs": usernameS,
                "enc_data": enc_data,
                "request_id": requestid
            })
        })
        let verifyData = await verifyResponse.json()
        if(verifyData.ERROR){
                store_status.innerText = verifyData.ERROR
            }
            else if(!verifyResponse.ok){
                store_status.innerText = "The password could not be stored. Please try again."
                return
            }
            else{
                store_status.innerText = "Stored succesfully"
                window.location.href = "#"
}
}



})
