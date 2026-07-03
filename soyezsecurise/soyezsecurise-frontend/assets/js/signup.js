const username = document.getElementById("username")

const masterPassword = document.getElementById("password")

const confirmPassword = document.getElementById("confirm-password")

const email = document.getElementById("email")

const signinbtn = document.getElementById("signinbtn")

const statusmsg = document.getElementById("status-signin")

const signupPasswordField = document.getElementById("signup-password-field")

const signupConfirmPasswordField = document.getElementById("signup-confirm-password-field")

const signupOtpField = document.getElementById("signup-otp-field")

const signupOtp = document.getElementById("signup-otp")

const signupStepPanel = document.getElementById("signup-step-panel")

let pendingSignupChallenge = null

async function hasher(password){
    
    let passwordbytes = new TextEncoder().encode(password)

    let saltBytes =
    crypto.getRandomValues(
    new Uint8Array(32)
    )
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

function showSignupSecretStep(){
    signupPasswordField.style.display = "block"
    signupConfirmPasswordField.style.display = "block"
    signupOtpField.style.display = "block"
    username.readOnly = true
    email.readOnly = true
    signinbtn.value = "Create vault"
    if(signupStepPanel){
        signupStepPanel.classList.add("otp-active")
    }
    masterPassword.focus()
}

function resetSignupFlow(){
    pendingSignupChallenge = null
    signupPasswordField.style.display = "none"
    signupConfirmPasswordField.style.display = "none"
    signupOtpField.style.display = "none"
    username.readOnly = false
    email.readOnly = false
    signinbtn.value = "Continue"
    signinbtn.disabled = false
    if(signupStepPanel){
        signupStepPanel.classList.remove("otp-active")
    }
    statusmsg.innerText = ""
}



document.getElementById("Sign-in").addEventListener(
"submit",
async function(e){
    e.preventDefault()
    signinbtn.disabled = true

    if(!pendingSignupChallenge){
        let usernameV = username.value.trim()
        let emailV = email.value.trim()

        if(!usernameV){
            statusmsg.innerText = "Enter your username."
            signinbtn.disabled = false
            return
        }

        if(!emailV){
            statusmsg.innerText = "Enter your email."
            signinbtn.disabled = false
            return
        }

        statusmsg.innerText = "Sending verification code..."

        try {
            let response = await fetch(`${server_link}/newuser1`,
                {
                    method:"POST",
                    headers:{
                        "Content-Type":
                        "application/json"
                    },
                    body:JSON.stringify(
                        {
                            "username": usernameV,
                            "email": emailV
                        }
                    )
                }
            )

            let data = await response.json()

            if(data.ERROR){
                statusmsg.innerText = data.ERROR
                signinbtn.disabled = false
                return
            }

            if(!response.ok){
                statusmsg.innerText = "Request failed"
                signinbtn.disabled = false
                return
            }

            pendingSignupChallenge = {
                username: usernameV,
                email: emailV,
                requestid: data.request_id || null
            }

            showSignupSecretStep()
            statusmsg.innerText = data["sent on"]
                ? "Verification code sent to " + data["sent on"] + ". Enter your OTP and master password."
                : "Verification code sent. Enter your OTP and master password."
            signinbtn.disabled = false
        }
        catch(error) {
            statusmsg.innerText = "Signup request failed: " + error.message
            signinbtn.disabled = false
        }

        return
    }

    let masterpassV = masterPassword.value
    let confirmPasswordV = confirmPassword.value
    let otpV = signupOtp.value.trim().toUpperCase()

    if(!masterpassV){
        statusmsg.innerText = "Enter your master password."
        signinbtn.disabled = false
        return
    }

    if(!confirmPasswordV){
        statusmsg.innerText = "Confirm your master password."
        signinbtn.disabled = false
        return
    }

    if(masterpassV !== confirmPasswordV){
        statusmsg.innerText = "Master passwords do not match."
        confirmPassword.focus()
        signinbtn.disabled = false
        return
    }

    if(!otpV){
        statusmsg.innerText = "Enter the OTP code sent to your email."
        signinbtn.disabled = false
        return
    }

    try {
        statusmsg.innerText = "Deriving keys..."
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

        statusmsg.innerText = "Preparing keys..."

        let authkey1bytes = new Uint8Array(authkey1)
        let authkey1hex = bytesToHex(authkey1bytes)
        let salthex = bytesToHex(result.saltBytes)

        let signupPayload = {
            "username": pendingSignupChallenge.username,
            "hash": authkey1hex,
            "email": pendingSignupChallenge.email,
            "salt": salthex,
            "otp": otpV
        }

        if(pendingSignupChallenge.requestid){
            signupPayload.request_id = pendingSignupChallenge.requestid
        }

        let response = await fetch(`${server_link}/newuser2`,
            {
                method:"POST",
                headers:{
                    "Content-Type":
                    "application/json"
                },
                body:JSON.stringify(signupPayload)
            }
        )

        let data = await response.json()

        if(data.ERROR){
            statusmsg.innerText = data.ERROR
            signinbtn.disabled = false
            return
        }

        if(!response.ok){
            statusmsg.innerText = "Request failed"
            signinbtn.disabled = false
            return
        }

        statusmsg.innerText = "User created. Continue to OTP setup."
        localStorage.setItem("username", pendingSignupChallenge.username)
        localStorage.setItem("authkey", authkey1hex)
        localStorage.setItem("userLoggedIn", "false")
        localStorage.removeItem("session_id")
        window.location.href = "enable-otp.html"
    }
    catch(error) {
        statusmsg.innerText = "Signup failed: " + error.message
        signinbtn.disabled = false
    }
}
)

document.getElementById("Sign-in").addEventListener("reset", resetSignupFlow)
