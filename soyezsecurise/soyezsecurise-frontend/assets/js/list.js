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

let response = await fetch("http://localhost:8000/list",
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
        loginbtn.disabled = false
    }
    else if(!response.ok){
        list_status.innerText = "Request failed"
        loginbtn.disabled = false
        return
    }
    else{
        let nonce = data_L.nonce
        let requestid = data_L.request_id
        let signature = await storegeneratesign(nonce, authkey_list)
        list_status.innerText = "Verifying"
        let listverifyResponse = await fetch("http://localhost:8000/list2",
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
            list_status.innerText = "Request failed"
            return
        }
        else{
            listbox.innerText = ""
            list_status.innerText = ""
            listverifyData.passwords.forEach(password=>{

            let li = document.createElement("li")

            li.innerText =
            `${password.service} (${password.username})`
            document.getElementById("passwordList").appendChild(li)
        })
        }
    }

})