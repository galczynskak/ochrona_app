const getFormValues = (form) => {
    let inputArray = [...form.querySelectorAll("input"), ...form.querySelectorAll("select")];
    let res = {}
    inputArray.forEach((item) => {
        res = {...res, [item.getAttribute("name")]: item.value}
    })
    return res;
}

const getHeaders = (token= null) => {
    let headers = {
        "Content-Type": "application/json"
    };
    if (token != null) {
        headers = {
            ...headers,
            "Authorization": `Token ${token}`
        };
    }
    return headers;
}


const flashAlert = (msg, variant= "danger") => {
    let alert = document.querySelector("div.alert");
    alert.classList.add(`alert-${variant}`);
    alert.innerText = msg;
    alert.hidden=true;
    alert.hidden=false;
    setTimeout( () =>{
        alert.hidden=true;
    }, 3000)
}