const menuButton = document.getElementById("menu-btn")
const menu = document.getElementById("menu")
const menuIcon = document.querySelector("#menu-btn .icon")
const loggedInMenu = document.getElementById("logged-in")
const loggedOutMenu = document.getElementById("logged-out")
const logoutRequest = document.getElementById("logoutrequest")

menuButton.addEventListener("click", function(){
    menu.classList.toggle("active")
})

// Update icon based on login state
function updateUserIcon() {
    const loggedIn = hasActiveSession()

    menuIcon.classList.toggle("fa-user", !loggedIn)
    menuIcon.classList.toggle("fa-gem", loggedIn)
    loggedInMenu.style.display = loggedIn ? "block" : "none"
    loggedOutMenu.style.display = loggedIn ? "none" : "block"
}

// Handle logout
logoutRequest.addEventListener("click", function(e) {
    e.preventDefault()
    clearSession()
    menu.classList.remove("active")
})

// Update icon on page load
document.addEventListener("DOMContentLoaded", updateUserIcon)

// Listen for storage changes (login/logout)
window.addEventListener("storage", updateUserIcon)
window.addEventListener(AUTH_STATE_EVENT, updateUserIcon)
