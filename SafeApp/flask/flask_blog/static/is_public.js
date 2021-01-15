checkIfPublic();
document.getElementById("is_public").oninput = () => {checkIfPublic();}

function checkIfPublic() {
    if (document.getElementById("is_public").checked){

        document.getElementById("is_encrypted").disabled = true;
        document.getElementById("is_encrypted").checked = false;

        document.getElementById("share").style.display = "none";
        document.getElementById("share").value = "";
        document.getElementById("share-label").style.display = "none";
    }
    else{
        document.getElementById("is_encrypted").disabled = false;

        document.getElementById("share").style.display = "initial";
        document.getElementById("share-label").style.display = "initial";
    }
}