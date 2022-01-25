let radio_value = 'privacyPrivate'

window.onload = () => {
    const privacyRadioList = document.querySelectorAll("input.form-check-input[name=notePrivacy]")
    const recipientElement = document.querySelector("#recipientsInput")
    privacyRadioList.forEach((radio) => {
        radio.addEventListener("change", function(){
            if (radio.checked) {
                radio_value = radio.id;
            }

            if (radio.checked && radio.id === 'privacyRestricted') {
                recipientElement.style.display = ""
            } else {
                recipientElement.style.display = "none"
            }
        })
    });
    let form = document.querySelector("form");
    document.addEventListener("submit", async(e) => handleNoteSubmit(e, form));
    document.querySelector('#a.logout-button').addEventListener('click', async (e) => handleLogoutClick(e));
}


const handleNoteSubmit = async(event, form) => {
    event.preventDefault();
    try {
        let res = await performNoteAdding({...getFormValues(form), radio_value});
        if (res.message) {
            flashAlert(res.message, "success")
        }
        window.setTimeout(function(){
            window.location.pathname = "/notes/my"
        }, 500);
    } catch (e) {
        flashAlert(e.message)
    }
};


const performNoteAdding = async (data) => {
    let res = await fetch("/add_note", {
        method: 'POST',
        body: JSON.stringify(data),
        headers: getHeaders()
    });

    if (res.status === 200) {
        return await res.json();
    } else {
        throw await res.json();
    }
}