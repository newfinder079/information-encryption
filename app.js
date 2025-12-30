// app.js

document.addEventListener('DOMContentLoaded', () => {
    const btnEncrypt = document.getElementById('btnEncrypt');
    const btnDecrypt = document.getElementById('btnDecrypt');
    const btnEncClear = document.getElementById('btnEncClear');
    const btnDecClear = document.getElementById('btnDecClear');
    const btnCopyCipher = document.getElementById('btnCopyCipher');
    const btnSelfTest = document.getElementById('btnSelfTest');

    btnEncrypt.addEventListener('click', encrypt);
    btnDecrypt.addEventListener('click', decrypt);
    btnEncClear.addEventListener('click', clearEncryptFields);
    btnDecClear.addEventListener('click', clearDecryptFields);
    btnCopyCipher.addEventListener('click', copyCipherText);
    btnSelfTest.addEventListener('click', selfTest);

    function encrypt() {
        const plainText = document.getElementById('plainIn').value;
        const password = document.getElementById('passEnc').value;
        const iterations = parseInt(document.getElementById('iterations').value, 10);
        // Implement encryption logic here
        const cipherText = `Encrypted(${plainText}) with ${iterations} iterations`; // Placeholder
        document.getElementById('cipherOut').value = cipherText;
        updateStatus('加密成功！');
    }

    function decrypt() {
        const cipherText = document.getElementById('cipherIn').value;
        const password = document.getElementById('passDec').value;
        // Implement decryption logic here
        const plainText = `Decrypted(${cipherText})`; // Placeholder
        document.getElementById('plainOut').value = plainText;
        updateStatus('解密成功！');
    }

    function clearEncryptFields() {
        document.getElementById('plainIn').value = '';
        document.getElementById('cipherOut').value = '';
        document.getElementById('passEnc').value = '';
    }

    function clearDecryptFields() {
        document.getElementById('cipherIn').value = '';
        document.getElementById('plainOut').value = '';
        document.getElementById('passDec').value = '';
    }

    function copyCipherText() {
        const cipherText = document.getElementById('cipherOut');
        cipherText.select();
        document.execCommand('copy');
        updateStatus('密文已复制！');
    }

    function selfTest() {
        const testText = '测试文本';
        const testPassword = '测试口令';
        document.getElementById('plainIn').value = testText;
        document.getElementById('passEnc').value = testPassword;
        encrypt();
        const cipherText = document.getElementById('cipherOut').value;
        document.getElementById('cipherIn').value = cipherText;
        document.getElementById('passDec').value = testPassword;
        decrypt();
    }

    function updateStatus(message) {
        document.getElementById('status').textContent = message;
    }
});