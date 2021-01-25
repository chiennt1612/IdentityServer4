$(function () {
    $('#Email').on('keypress', function (e) {
        if (e.which == 13) {
            var u = document.forms[0].elements["Username"];
            if (this.value != "" && u.value == "") {
                if (this.value.indexOf("@") > -1) {
                    u.value = this.value.substr(0, this.value.indexOf("@"));
                } else {
                    u.value = this.value;
                }
            }
            this.value = this.value.toLowerCase();
        }
    });

    $('#Username').on('keypress', function (e1) {
        if (e1.which == 13) {
            var e = document.forms[0].elements["Email"];
            if (this.value != "" && e.value == "") {
                if (this.value.indexOf("@") < 0) {
                    e.value = this.value + "@gmail.com";
                } else {
                    e.value = this.value;
                }
            }
            this.value = this.value.toLowerCase();
        }
    });
});

var defaultRangeValidator = $.validator.methods.range;
$.validator.methods.range = function (value, element, param) {
    if (element.type === 'checkbox') {
        return element.checked;
    } else {
        return defaultRangeValidator.call(this, value, element, param);
    }
}

//function setUsername(e, _u) {
//    var u = document.forms[0].elements[_u];
//    if (e.value != "" && u.value == "") {
//        if (e.value.indexOf("@") > -1) {
//            u.value = e.value.substr(0, e.value.indexOf("@"));
//        } else {
//            u.value = e.value;
//        }
//    }
//}

//function setEmail(u, _e) {
//    var e = document.forms[0].elements[_e];
//    if (u.value != "" && e.value == "") {
//        if (e.value.indexOf("@") < 0) {
//            u.value = e.value + "@gmail.com";
//        } else {
//            u.value = e.value;
//        }
//    }
//}