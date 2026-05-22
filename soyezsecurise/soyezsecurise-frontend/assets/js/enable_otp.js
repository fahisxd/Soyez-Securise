const otp_link = document.getElementById("otpenabling-link");
const doneotpbtn = document.querySelector(".primary")


function warnUser(e){

    e.preventDefault()

    e.returnValue = true

}

function bytesToHex(bytes){
    return Array.from(bytes).map(
        byte =>
        byte.toString(16)
        .padStart(2,"0")
    ).join("")
}

function copyotp(){

    let secret =
    document.getElementById(
    "otp-secret"
    )

    navigator.clipboard.writeText(
        secret.value
    )
}

async function otpgeneratesign(noncehex, keyhex){
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



window.addEventListener(
"beforeunload",

function(e){
    e.preventDefault()
})

document.addEventListener("DOMContentLoaded",async function(){
let otp_username = localStorage.getItem("username")

if(otp_username !== null){
    let otp_key = localStorage.getItem("authkey")
    if(otp_key !== null){
    let response = await fetch("http://localhost:8000/enableotp",
    {
        method:"POST",
        headers:{
            "Content-Type":
            "application/json"
        },
        body:JSON.stringify({
            "username": otp_username
        })}
    

)

    let data = await response.json()

        if(data.ERROR){
        otp_link.href = "#otp-error";

    }

        else if(response.status !== 200){
            otp_link.href = "#otp-error";
            return
        }

        else{
            nonce = data.nonce
            requestid = data.request_id
            signature = await otpgeneratesign(nonce, otp_key)
            let verifyResponse = await fetch("http://localhost:8000/enable_otp2",
            {
            method:"POST",

            headers:{
                "Content-Type":
                "application/json"
            },
            body:JSON.stringify({
                "signature": signature,
                "username": otp_username,
                "request_id": requestid
            })
        })
        let verifyData = await verifyResponse.json()
            if(verifyResponse.status !== 200){
                    otp_link.href = "#otp-error";
                    return
                }
            if(verifyData.ERROR){
                    if(verifyData.ERROR == "otp Already enabled"){
                        window.location.href = "main.html"
                    }
                    else{
                        otp_link.href = "#otp-error";
                        return
                    }

                }
            
            else{
                  let qrimg = document.getElementById("qr")
                  qrimg.src = "data:image/png;base64," + verifyData.qr
                  otp_link.href = "#otp-scanner";
                  document.getElementById("otp-secret").value = verifyData.secret_code
                }
}


}
}


})

window.addEventListener(
    "beforeunload",
    warnUser
)


document.getElementById("otp").addEventListener(
"submit",
async function(e){
e.preventDefault()
doneotpbtn.disabled = true
window.addEventListener(
    "beforeunload",
    warnUser
)

window.location.href = "main.html"

})
