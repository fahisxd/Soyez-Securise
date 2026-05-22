const username_del = document.getElementById("usernameD")

const usernameD = document.getElementById("user-nameSD")

const servicename_D = document.getElementById("password-nameD")

const del_status = document.getElementById("status-del")

const delpasswordfunc = document.getElementById("deletepassword")


//start from here
document.getElementById("deletepassword").addEventListener("click",
async function(e){
    e.preventDefault() 
    if(window.vaultkey){
        delpasswordfunc.href = "#Deletepassword"
        window.location.href = "#Deletepassword"
    }
    else{
        delpasswordfunc.href = "#login"
        window.location.href = "#login"
    }
})

document.getElementById("delete-password").addEventListener("submit",
    async function(e){
        e.preventDefault()
        del_status.innerText = "getting Values...."
        let usernameDV = username_del.value
        let usernameDVS = usernameD.value
        let service_nameDV = servicename_D.value
        del_status.innerText = "Requesting server...."
        let response = await fetch("http://localhost:8000/delete",
            {
                method:"POST",
                headers:{
                    "Content-Type":"application/json"
            },
            body:JSON.stringify({
                    username:usernameDV
                })
            })
        let deldata = await response.json()
        if(deldata.ERROR){
        get_status.innerText = deldata.ERROR
        loginbtn.disabled = false
        }
        else if(!response.ok){
            del_status.innerText = "Request failed"
            loginbtn.disabled = false
            return
        }
        else{
            let nonce = deldata.nonce
            let requestid = deldata.request_id
            let authkey = localStorage.getItem("authkey")
            let signature = await storegeneratesign(nonce, authkey)
            del_status.innerText = "Verifying"
            let delverifyResponse = await fetch("http://localhost:8000/delete2",
            {
                method:"POST",

                headers:{
                "Content-Type":
                "application/json"
                },
                body:JSON.stringify({
                    signature:signature,
                    username:usernameDV,
                    password_name:service_nameDV,
                    usernameS:usernameDVS,
                    request_id:requestid

                    })
            })
            let delverifyData = await delverifyResponse.json()
            if(delverifyData.ERROR){
                del_status.innerText = getverifyData.ERROR
                return
            }
            else if(!delverifyResponse.ok){
                del_status.innerText = "Request failed"
                return
            }
            else{
                del_status.innerText = "password deleted succesfully"
            }

        }








})

