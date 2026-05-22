const notLoggedInDiv = document.getElementById("profile-not-logged-in")
const loggedInDiv = document.getElementById("profile-logged-in")
const usernameSpan = document.getElementById("usernameP")
const profileStatusMsg = document.getElementById("profile-status-msg")
const profilePasswordCount = document.getElementById("profile-password-count")
const profileLastModified = document.getElementById("profile-last-modified")
const twoFAStatus = document.getElementById("2fa-status")
const profileLogoutBtn = document.getElementById("profile-logout-btn")

function updateProfileDisplay() {
    const username = localStorage.getItem("username")
    const userLoggedIn = localStorage.getItem('userLoggedIn') === 'true'
    
    if (!username || !userLoggedIn) {
        notLoggedInDiv.style.display = "block"
        loggedInDiv.style.display = "none"
        return
    }
    

    notLoggedInDiv.style.display = "none"
    loggedInDiv.style.display = "block"
    usernameSpan.innerText = username

    loadPasswordCount(username)
}


async function loadPasswordCount(username) {
    try {
        profileStatusMsg.innerText = "Loading vault statistics..."
        const authkey = localStorage.getItem("authkey")
        
        if (!authkey) {
            profileStatusMsg.innerText = "Error: Authentication key not found"
            return
        }
        

        let response = await fetch("http://localhost:8000/list", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username: username
            })
        })
        
        let data = await response.json()
        
        if (data.ERROR) {
            profileStatusMsg.innerText = "Error: " + data.ERROR
            return
        }
        
        if (!response.ok) {
            profileStatusMsg.innerText = "Error loading statistics"
            return
        }
        
        let nonce = data.nonce
        let requestid = data.request_id
        let signature = await storegeneratesign(nonce, authkey)
        
        let listverifyResponse = await fetch("http://localhost:8000/list2", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                signature: signature,
                username: username,
                request_id: requestid
            })
        })
        
        let listverifyData = await listverifyResponse.json()
        
        if (listverifyData.ERROR) {
            profileStatusMsg.innerText = "Error: " + listverifyData.ERROR
            return
        }
        
        if (!listverifyResponse.ok) {
            profileStatusMsg.innerText = "Error loading password list"
            return
        }
        

        if (listverifyData.passwords) {
            profilePasswordCount.innerText = listverifyData.passwords.length
            
            if (listverifyData.passwords.length > 0) {
                profileLastModified.innerText = "Recently"
            } else {
                profileLastModified.innerText = "No passwords stored yet"
            }
        }
        
        profileStatusMsg.innerText = ""
        
    } catch (error) {
        profileStatusMsg.innerText = "Error loading statistics: " + error.message
    }
}





profileLogoutBtn.addEventListener('click', function(e) {
    e.preventDefault()
    localStorage.setItem('userLoggedIn', 'false')
    localStorage.removeItem('username')
    localStorage.removeItem('authkey')
    window.location.href = "#login"
    updateProfileDisplay()
})


document.addEventListener('DOMContentLoaded', function() {
    updateProfileDisplay()
    check2FAStatus()
})


window.addEventListener('storage', function() {
    updateProfileDisplay()
    check2FAStatus()
})
