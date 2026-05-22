// Toggle menu visibility
document
.getElementById(
"user-button"
)

.onclick=()=>{

document
.getElementById(
"menu"
)

.classList
.toggle(
"active")

}

// Update icon based on login state
function updateUserIcon() {
  const loggedIn = localStorage.getItem('userLoggedIn') === 'true';
  const iconSpan = document.querySelector('#menu-btn .icon');
  const loggedInDiv = document.getElementById('logged-in');
  const loggedOutDiv = document.getElementById('logged-out');
  
  if (loggedIn) {
    // Logged in - show diamond
    iconSpan.classList.remove('fa-user');
    iconSpan.classList.add('fa-gem');
    loggedInDiv.style.display = 'block';
    loggedOutDiv.style.display = 'none';
  } else {
    // Logged out - show user icon
    iconSpan.classList.remove('fa-gem');
    iconSpan.classList.add('fa-user');
    loggedInDiv.style.display = 'none';
    loggedOutDiv.style.display = 'block';
  }
}

// Handle logout
document.getElementById('logoutrequest').addEventListener('click', function(e) {
  e.preventDefault();
  localStorage.setItem('userLoggedIn', 'false');
  localStorage.removeItem('username');
  localStorage.removeItem('authkey');
  updateUserIcon();
  document.getElementById('menu').classList.remove('active');
});

// Update icon on page load
document.addEventListener('DOMContentLoaded', updateUserIcon);

// Listen for storage changes (login/logout)
window.addEventListener('storage', updateUserIcon);