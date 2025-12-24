from flask import Flask, render_template_string, request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

app = Flask(__name__)

# ================== Fungsi Membuat Key 256-bit ==================
def derive_key(text_key):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(text_key.encode())
    return digest.finalize()


# ================== HTML UI ==================
html = """
<!DOCTYPE html>
<html>
<head>
<title>AES Encrypt / Decrypt</title>

<style>
body{
    font-family: Arial;
    background:#0b1220;
    color:white
}

.container{
    width:600px;
    margin:auto;
    margin-top:40px;
    padding:20px;
    background:#141e30;
    border-radius:15px
}

textarea,input{
    width:100%;
    padding:10px;
    border-radius:10px;
    border:none
}

button{
    padding:10px 20px;
    border:none;
    border-radius:10px;
    background:#4e73df;
    color:white;
    margin-top:10px
}
</style>
</head>

<body>
<div class="container">

<h2 align="center">AES Encrypt / Decrypt</h2>

<form method="post">

<label>Key</label>
<input name="key" placeholder="Masukkan key bebas">

<label>Text</label>
<textarea name="text" rows="4">{{text}}</textarea>

<select name="mode">
    <option value="encrypt">Encrypt</option>
    <option value="decrypt">Decrypt</option>
</select>

<button type="submit">Proses</button>
</form>

{% if result %}
<h3>Hasil:</h3>
<textarea rows="4">{{result}}</textarea>
{% endif %}

</div>
</body>
</html>
"""


# ================== ROUTE ==================
@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    text = ""

    if request.method == "POST":
        text = request.form["text"]
        key = derive_key(request.form["key"])
        mode = request.form["mode"]

        # ========== ENCRYPT ==========
        if mode == "encrypt":
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            ct = encryptor.update(text.encode()) + encryptor.finalize()

            # gabungkan IV + ciphertext
            result = base64.b64encode(iv + ct).decode()

        # ========== DECRYPT ==========
        else:
            raw = base64.b64decode(text)
            iv = raw[:16]
            ct = raw[16:]

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            result = (decryptor.update(ct) + decryptor.finalize()).decode()

    return render_template_string(html, result=result, text=text)


# ================== RUN ==================
if __name__ == "__main__":
    app.run(debug=True)
