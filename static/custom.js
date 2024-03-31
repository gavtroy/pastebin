$(document).ready(function() {
    function replaceUrlParam(url, param, value) {
        if (value == null) {
            value = '';
        }

        var pattern = new RegExp('\\b('+param+'=).*?(&|#|$)');
        if (url.search(pattern)>=0) {
            return url.replace(pattern,'$1' + value + '$2');
        }

        url = url.replace(/[?#]$/,'');
        return url + (url.indexOf('?')>0 ? '&' : '?') + param + '=' + value;
    }

    function resetLanguageSelector() {
        var url = new URL(document.location);
        var lang = url.searchParams.get("lang");
        if (!lang) {
            lang = $("#pastebin-code-block").prop("class");
        }
        if (!lang) {
            return;
        }
        langs = lang.trim().split('-');
        lang = langs.pop();
        diff = langs.pop() == "diff";

        $("#diff-button").toggleClass('active', diff);
        $("#diff-button").attr('aria-pressed', $("#diff-button").hasClass('active'))
        $("#language-selector").val(lang);
    }

    function getDefaultExpiryTime() {
        var expiry = $("#expiry-dropdown-btn").text().split("Expires: ")[1];
        return $("#expiry-dropdown a:contains('"+ expiry +"')").attr('href');
    }

    function checkPasswordModal() {
        if ($("#password-modal").length) {
            $('#password-modal').modal('toggle');
        }
    }

    resetLanguageSelector();
    checkPasswordModal();
    init_plugins();

    var state = {
        expiry: getDefaultExpiryTime(),
        burn: 0,
    };

    window.history.replaceState(null, null, window.location.pathname + window.location.hash);

    function languageChanged() {
        if ($("#pastebin-code-block").length) {
            diff_tag = $("#diff-button").hasClass("active") ? "diff-" : "";
            $('#pastebin-code-block').attr('class', 'language-' + diff_tag + $("#language-selector").val());
            init_plugins();
        }
    }

    $("#diff-button").click(function(event) {
        $(this).toggleClass('active');
        $(this).attr('aria-pressed', $(this).hasClass('active'))
        languageChanged();
    });

    $("#language-selector").change(languageChanged);

    $("#remove-btn").on("click", function(event) {
        event.preventDefault();
        $('#deletion-modal').modal('show');
    });

    $("#deletion-confirm-btn").on("click", function(event) {
        event.preventDefault();

        $.ajax({
            url: window.location.pathname,
            type: 'DELETE',
            success: function(result) {
                uri = uri_prefix + "/new";
                uri = replaceUrlParam(uri, 'level', "secondary");
                uri = replaceUrlParam(uri, 'glyph', "fas fa-info-circle");
                uri = replaceUrlParam(uri, 'msg', "The paste has been successfully removed.");
                window.location.href = encodeURI(uri);
            }
        });
    });

    $("#copy-btn").on("click", function(event) {
        event.preventDefault();

        $(".toolbar-item button").get(0).click();

        var $this = $(this);
        $this.text("Copied!");
        $this.attr("disabled", "disabled");

        setTimeout(function() {
            $this.text("Copy");
            $this.removeAttr("disabled");
        }, 800);

    });

    $("#pastebin-password").on("keydown", function(event) {
        if (event.key === 'Enter') {
            $("#send-btn").click();
        }
    });

    async function blobToBase64(blob) {
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = (event) => {
                const dataUrl = event.target.result;
                const [_, base64] = dataUrl.split(',');
                resolve(base64);
            };
            reader.readAsDataURL(blob);
        });
    }

    async function base64ToBytes(str) {
        const dataUrl = "data:application/octet-stream;base64," + str;
        const res = await fetch(dataUrl);
        return new Uint8Array(await res.arrayBuffer());
    }

    async function deriveKey(salt, password) {
        const pass = new TextEncoder().encode(password);
        const keymat_in = await window.crypto.subtle.importKey("raw", pass, "PBKDF2", false, ["deriveBits"]);

        const kdf_params = { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: 100000 };
        const keymat_out = await window.crypto.subtle.deriveBits(kdf_params, keymat_in, 256+96);
        const key_raw = keymat_out.slice(0, 32);
        const key = await window.crypto.subtle.importKey("raw", key_raw, "AES-GCM", false, ["encrypt", "decrypt"]);
        const iv = keymat_out.slice(32, 44);

        return [key, iv];
    }

    async function encrypt(data, pass) {
        const salt = window.crypto.getRandomValues(new Uint8Array(12));
        const [key, iv] = await deriveKey(salt, pass);
        const message = new TextEncoder().encode(data);
        const ciphertext = window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, message);
        return blobToBase64(new Blob(["v1", salt, await ciphertext]));
    }

    async function decrypt(data, pass) {
        const bytes = await base64ToBytes(data);
        const salt = bytes.slice(2, 14);
        const ciphertext = bytes.slice(14);
        const [key, iv] = await deriveKey(salt, pass);
        const message = window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);
        return new TextDecoder().decode(await message);
    }

    $("#send-btn").on("click", async function(event) {
        event.preventDefault();

        diff_tag = $("#diff-button").hasClass("active") ? "diff-" : "";
        uri = uri_prefix == "" ? "/" : uri_prefix;
        uri = replaceUrlParam(uri, 'lang', diff_tag + $("#language-selector").val());
        uri = replaceUrlParam(uri, 'ttl', state.expiry);
        uri = replaceUrlParam(uri, 'burn', state.burn);

        var data = $("#content-textarea").val();
        var pass = $("#pastebin-password").val();

        if (pass.length > 0) {
            data = await encrypt(data, pass);
            uri = replaceUrlParam(uri, 'encrypted', true);
        }

        $.ajax({
            url: uri,
            type: 'POST',
            data: data,
            success: function(result) {
                if (state.burn) {
                    uri = uri_prefix + "/new";
                    uri = replaceUrlParam(uri, 'level', "success");
                    uri = replaceUrlParam(uri, 'glyph', "fas fa-check");
                    uri = replaceUrlParam(uri, 'msg', "The paste has been successfully created:");
                    uri = replaceUrlParam(uri, 'url', result);

                    window.location.href = encodeURI(uri);
                } else {
                    window.location.href = result;
                }
            }
        });
    });

    $('#expiry-dropdown a').click(function(event){
        event.preventDefault();

        state.expiry = $(this).attr("href");
        $('#expiry-dropdown-btn').text("Expires: " + this.innerHTML);
    });

    $('#burn-dropdown a').click(function(event){
        event.preventDefault();

        state.burn = $(this).attr("href");
        $('#burn-dropdown-btn').text("Burn: " + this.innerHTML);
    });

    $('#password-modal').on('shown.bs.modal', function () {
        $('#modal-password').trigger('focus');
    })

    $('#password-modal form').submit(function(event) {
        event.preventDefault();
        $('#decrypt-btn').click();
    });

    $('#decrypt-btn').click(async function(event) {
        var pass = $("#modal-password").val();
        var data = "";

        if ($("#pastebin-code-block").length) {
            data = $("#pastebin-code-block").text();
        } else {
            data = $("#content-textarea").text();
        }

        let decrypted;
        try {
            if (data.startsWith("U2FsdGVkX1")) {
                // legacy CryptoJS pastes
                await new Promise((resolve) => {
                    var script = document.createElement('script');
                    script.src = "https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js";
                    script.onload = resolve;
                    document.head.appendChild(script);
                });
                decrypted = CryptoJS.AES.decrypt(data, pass).toString(CryptoJS.enc.Utf8);
                if (decrypted.length == 0) {
                    throw new Error("wrong password or empty paste");
                }
            } else {
                decrypted = await decrypt(data, pass);
            }
        } catch (error) {
            $("#modal-alert").removeClass("collapse");
            return;
        }
        if ($("#pastebin-code-block").length) {
            $("#pastebin-code-block").text(decrypted);
            init_plugins();
        } else {
            $("#content-textarea").text(decrypted);
        }

        $("#modal-close-btn").click();
        $("#modal-alert").alert('close');
    });
});
