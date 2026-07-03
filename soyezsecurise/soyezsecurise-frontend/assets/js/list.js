const list_status = document.getElementById("status-list")

const listpasswordfunc = document.getElementById("listpassword")

let listbox = document.getElementById("passwordList")

document.getElementById("listpassword").addEventListener("click",
async function(e){
    e.preventDefault() 
    listpasswordfunc.href = hasActiveSession() && window.vaultkey ? "#list" : "#login"
    if(!goToVaultRoute("#list")){
        return
    }

const username_L = localStorage.getItem("username")
const authkey_list = localStorage.getItem("authkey")

let response = await fetch(`${server_link}/list`,
    {
        method:"POST",
        headers:{
            "Content-Type":"application/json"
            },
        body:JSON.stringify(withSession({
            username: username_L
        }))
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
        let signature = await generateSignature(nonce, authkey_list)
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
                    session_id: getSessionId(),
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
            li.className = "vault-item"

            let meta = document.createElement("div")
            meta.className = "vault-item-meta"

            let service = document.createElement("strong")
            service.innerText = password.service

            let account = document.createElement("span")
            account.innerText = password.username

            let actions = document.createElement("div")
            actions.className = "vault-item-actions"

            let retrieve = document.createElement("a")
            retrieve.href = "#Getpassword"
            retrieve.className = "button small"
            retrieve.innerText = "Retrieve"
            retrieve.addEventListener("click", function(){
                document.getElementById("getp-username").value = username_L || ""
                document.getElementById("getp-usernameS").value = password.username
                document.getElementById("Servicename_G").value = password.service
            })

            let hint = document.createElement("a")
            hint.href = "#Hintpassword"
            hint.className = "button small"
            hint.innerText = "Hint"
            hint.addEventListener("click", function(){
                document.getElementById("hint-username").value = username_L || ""
                document.getElementById("hint-service-name").value = password.service
            })

            meta.appendChild(service)
            meta.appendChild(account)
            actions.appendChild(retrieve)
            actions.appendChild(hint)
            li.appendChild(meta)
            li.appendChild(actions)
            document.getElementById("passwordList").appendChild(li)
        })
        }
    }

})
