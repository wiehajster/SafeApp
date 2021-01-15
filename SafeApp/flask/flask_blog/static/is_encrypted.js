checkIfEncrypted()
document.getElementById("is_encrypted").oninput = () => {checkIfEncrypted();}

function checkIfEncrypted() {
    if (document.getElementById("is_encrypted").checked){
        document.getElementById("is_public").disabled = true;

        document.getElementById("share").style.display = "none";
        document.getElementById("share").value = "";
        document.getElementById("share-label").style.display = "none";

        document.getElementById("password_label").style.display = "initial";
        document.getElementById("confirm_password_label").style.display = "initial";
        document.getElementById("password").style.display = "initial";
        document.getElementById("confirm_password").style.display = "initial";      
    }
    else{
        document.getElementById("is_public").disabled = false;

        document.getElementById("share").style.display = "initial";
        document.getElementById("share-label").style.display = "initial";

        document.getElementById("password_label").style.display = "none";
        document.getElementById("confirm_password_label").style.display = "none";  
        document.getElementById("password").style.display = "none";
        document.getElementById("confirm_password").style.display = "none";   
    }
}
