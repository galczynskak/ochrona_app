window.onload = () => {
    let form = document.querySelector("form");
    document.addEventListener("submit", async(e) => submitRegistration(e, form));
    document.querySelector("input#registerPassword").addEventListener("input",  (e) => checkPasswordStrength(e));
}

const submitRegistration = async function(event, form) {
    event.preventDefault();
    try {
        let res = await performRegistration(getFormValues(form));
        if (res && res.message) {
            flashAlert(res.message, "success")
        }
        window.setTimeout(function(){
            window.location.pathname = "/login"
        }, 3000);
    } catch (exception) {
        flashAlert(exception.message);
    }
}


const performRegistration = async(data) => {
    let res = await fetch("/register", {
        method: "POST",
        body: JSON.stringify(data),
        headers: getHeaders()
    });

    if (res.status === 200) {
        return await res.json();
    } else {
        throw await res.json();
    }
}

const checkPasswordStrength = (e) => {
    let currentPass = e.target.value;
    let pattern1 = /[A-Z]/;
    let pattern2 = /[a-z]/
    let pattern3 = /[0-9]/;
    let pattern4 = /[!@#$%^&*()_-]/;

    let value = ((currentPass.match(pattern1) != null) +
        (currentPass.match(pattern2) != null) +
        (currentPass.match(pattern3) != null) +
        (currentPass.match(pattern4) != null) +
        (currentPass.length >= 8))

    updatePasswordStrength(value, document.querySelector("p#passwordStrength"))
}

const updatePasswordStrength = (value, passwordStrengthElement) => {
    let message = "Password "

    if (value <= 2) {
        message += "is too weak!";
        passwordStrengthElement.className = "weak";
    } else if (value <= 4) {
        message += "could be better...";
        passwordStrengthElement.className = "moderate";
    } else {
        message += "is safe!";
        passwordStrengthElement.className = "strong";
    }

    passwordStrengthElement.innerText = message;
}