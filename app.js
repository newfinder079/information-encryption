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

    // 将密码派生为密钥
    async function deriveKey(password, salt, iterations) {
        const encoder = new TextEncoder();
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iterations,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // 加密函数
    async function encrypt() {
        try {
            const plainText = document.getElementById('plainIn').value;
            const password = document.getElementById('passEnc').value;
            const iterations = parseInt(document.getElementById('iterations').value, 10);

            if (!plainText) {
                updateStatus('请输入要加密的明文！');
                return;
            }

            if (!password) {
                updateStatus('请输入口令！');
                return;
            }

            // 生成随机盐和IV
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));

            // 派生密钥
            const key = await deriveKey(password, salt, iterations);

            // 加密数据
            const encoder = new TextEncoder();
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encoder.encode(plainText)
            );

            // 将迭代次数、盐、IV和密文组合在一起
            const result = new Uint8Array(4 + salt.length + iv.length + encrypted.byteLength);
            const view = new DataView(result.buffer);
            
            // 前4字节存储迭代次数
            view.setUint32(0, iterations, false);
            result.set(salt, 4);
            result.set(iv, 4 + salt.length);
            result.set(new Uint8Array(encrypted), 4 + salt.length + iv.length);

            // 转换为Base64
            const cipherText = btoa(String.fromCharCode(...result));
            document.getElementById('cipherOut').value = cipherText;
            updateStatus('加密成功！');
        } catch (error) {
            updateStatus(`加密失败：${error.message}`);
            console.error(error);
        }
    }

    // 解密函数
    async function decrypt() {
        try {
            const cipherText = document.getElementById('cipherIn').value;
            const password = document.getElementById('passDec').value;

            if (!cipherText) {
                updateStatus('请输入要解密的密文！');
                return;
            }

            if (!password) {
                updateStatus('请输入口令！');
                return;
            }

            // 从Base64解码
            const data = Uint8Array.from(atob(cipherText), c => c.charCodeAt(0));
            
            // 提取迭代次数、盐、IV和密文
            const view = new DataView(data.buffer);
            const iterations = view.getUint32(0, false);
            const salt = data.slice(4, 20);
            const iv = data.slice(20, 32);
            const encrypted = data.slice(32);

            // 派生密钥
            const key = await deriveKey(password, salt, iterations);

            // 解密数据
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encrypted
            );

            // 转换为文本
            const decoder = new TextDecoder();
            const plainText = decoder.decode(decrypted);
            document.getElementById('plainOut').value = plainText;
            updateStatus('解密成功！');
        } catch (error) {
            updateStatus(`解密失败：口令错误或密文已损坏`);
            console.error(error);
        }
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

    async function copyCipherText() {
        const cipherText = document.getElementById('cipherOut').value;
        
        if (!cipherText) {
            updateStatus('没有可复制的密文！');
            return;
        }

        try {
            await navigator.clipboard.writeText(cipherText);
            updateStatus('密文已复制到剪贴板！');
        } catch (error) {
            // 降级方案：使用旧方法
            const textarea = document.getElementById('cipherOut');
            textarea.select();
            try {
                document.execCommand('copy');
                updateStatus('密文已复制到剪贴板！');
            } catch (e) {
                updateStatus('复制失败，请手动选择并复制');
            }
        }
    }

    async function selfTest() {
        try {
            const testText = '测试文本123ABC!@#\n多行测试';
            const testPassword = '测试口令';
            const testIterations = 100000;
            
            document.getElementById('plainIn').value = testText;
            document.getElementById('passEnc').value = testPassword;
            document.getElementById('iterations').value = testIterations;
            
            updateStatus('正在运行自检：加密中...');
            await encrypt();
            
            await new Promise(resolve => setTimeout(resolve, 500));
            
            const cipherText = document.getElementById('cipherOut').value;
            if (!cipherText) {
                updateStatus('自检失败：加密未产生密文');
                return;
            }
            
            document.getElementById('cipherIn').value = cipherText;
            document.getElementById('passDec').value = testPassword;
            
            updateStatus('正在运行自检：解密中...');
            await decrypt();
            
            await new Promise(resolve => setTimeout(resolve, 500));
            
            const decryptedText = document.getElementById('plainOut').value;
            if (decryptedText === testText) {
                updateStatus('✓ 自检通过！加密和解密功能正常工作。');
            } else {
                updateStatus('✗ 自检失败：解密结果与原文不匹配');
            }
        } catch (error) {
            updateStatus(`自检失败：${error.message}`);
            console.error(error);
        }
    }

    function updateStatus(message) {
        document.getElementById('status').textContent = message;
    }
});