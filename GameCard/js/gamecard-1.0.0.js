function XHRSend(method, apiURL, sendData = "") {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (xhr.readyState == 4 && xhr.status == 200) {
            var response = JSON.parse(xhr.responseText);
            return response;
        }
    };
    xhr.open(method, apiURL, true);
    xhr.send(sendData);
}

function ElementSec(elementID) {
    if (elementID.includes('#')) {
        var id = "";
        var stringSplit = elementID.split('');
        for (i = 1; i <= stringSplit.length - 1; i++) {
            id += stringSplit[i];
        }
        return document.getElementById(id);
    }
}
function ToastCreate(title,message,alertType){
    VanillaToasts.create({
        title:title,
        text:message,
        type:alertType
    });

}