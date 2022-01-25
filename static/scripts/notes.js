window.onload = () => {
    document.querySelector('a#logout-button').addEventListener('click', async (e) => handleLogoutClick(e));
    document.querySelectorAll("form").forEach(x => {
        document.addEventListener("submit", async(e) => {
            e.preventDefault();
            try {
                const {content} = await handleNotePassword(getFormValues(x));
                x.parentElement.innerText = content;
            } catch(ex) {
                flashAlert(ex.message);
            }
        })
    })
};

const handleNotePassword = async(form) => {
    const url = '/note/auth';
    const res = await fetch(url, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify(form)
    });
    if (res.status === 200) {
        return await res.json()
    } else {
        throw await res.json()
    }
}