document.getElementById("password").oninput = () => {checkPassStrength();}

function checkPassStrength(){
    var pass = document.getElementById("password").value;

    var H = entropy(pass);
    var elem_class = "progress-bar ";
    var text = "";

    var variations = {
        length: pass.length >= 8,
        digits: /\d/.test(pass),
        lower: Array.from(pass).some(c => c == c.toLowerCase()),
        upper: Array.from(pass).some(c => c == c.toUpperCase()),
        nonWords: /\W/.test(pass)
    }

    var score = 0;
    for (var check in variations) {
        result = (variations[check] == true) ? 1 : 0;
        score += result;
    }

    if (pass.length == 0){
        elem_class += "bg-danger empty";
        text = "";
    }

    else if (score < 5 || H < 2.0){
        elem_class += "bg-danger very-weak";
        text = "bardzo słabe";
    }
    else if (H < 2.5){
        elem_class += "weak";
        text = "słabe";
    }
    else if (H < 3.5){
        elem_class += "bg-warning reasonable";
        text = "średnie";
    }
    else if (H >= 3.5) {
        elem_class += "bg-success strong";
        text = "mocne";
    }
    document.getElementById("progress-bar").className = elem_class;
    document.getElementById("password_strength").innerHTML = text;
}

function entropy(pass){
    var stat = {};
    for (var i=0; i<pass.length; i++) {
        c = pass[i]
        if (c in stat)
            stat[c] += 1
        else
            stat[c] = 1
    }
    var H = 0.0
    for(var key in stat) {
        var pi = stat[key]/pass.length;
        H -= pi * Math.log2(pi)
    }
    return H
}

