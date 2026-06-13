const username_L = localStorage.getItem("username")

const authkey_list = localStorage.getItem("authkey")

const list_status = document.getElementById("status-list")

const listpasswordfunc = document.getElementById("listpassword")

let listbox = document.getElementById("passwordList")

document.getElementById("listpassword").addEventListener("click",
async function(e){
    e.preventDefault() 
    if(window.vaultkey){
        listpasswordfunc.href = "#list"
        window.location.href = "#list"
    }
    else{
        listpasswordfunc.href = "#login"
        window.location.href = "#login"
    }

let response = await fetch(`${server_link}/list`,
    {
        method:"POST",
        headers:{
            "Content-Type":"application/json"
            },
        body:JSON.stringify({
            username: username_L
        })
    })
    let data_L = await response.json()
    if(data_L.ERROR){
        list_status.innerText = data_L.ERROR
        return
    }
    else if(!response.ok){
        list_status.innerText = "The server could not load your vault. Please try again."
        return
    }
    else{
        let nonce = data_L.nonce
        let requestid = data_L.request_id
        let signature = await storegeneratesign(nonce, authkey_list)
        list_status.innerText = "Verifying"
        let listverifyResponse = await fetch(`${server_link}/list2`,
            {
                method:"POST",

                headers:{
                "Content-Type":
                "application/json"
                },
                body:JSON.stringify({
                    signature:signature,
                    username:username_L,
                    request_id: requestid
                    })
            })
        let listverifyData = await listverifyResponse.json()
        if(listverifyData.ERROR){
                list_status.innerText = listverifyData.ERROR
            }
        else if(!listverifyResponse.ok){
            list_status.innerText = "Your vault could not be verified. Please try again."
            return
        }
        else{
            listbox.innerText = ""
            list_status.innerText = ""
            if (!Array.isArray(listverifyData.passwords)) {
                list_status.innerText = "The server returned an incomplete vault response."
                return
            }

            if (listverifyData.passwords.length === 0) {
                list_status.innerText = "Your vault is empty."
                return
            }

            listverifyData.passwords.forEach(password=>{

            let li = document.createElement("li")

            li.innerText =
            `${password.service} (${password.username})`
            document.getElementById("passwordList").appendChild(li)
        })
        }
    }

})
