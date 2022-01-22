window.onload = function() {
    const privacyRadioList = document.querySelectorAll("input.form-check-input[name=notePrivacy]")
    const recipientElement = document.querySelector("#recipientsInput")
    privacyRadioList.forEach((radio) => {
        radio.addEventListener("change", function(){
            if (radio.checked && radio.id === 'privacyRestricted') {
                recipientElement.style.display = ""
            } else {
                recipientElement.style.display = "none"
            }
        })
    })
}