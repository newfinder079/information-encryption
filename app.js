// app.js

document.addEventListener('DOMContentLoaded', () => {
    // 常量定义
    const CHAR_MAP = ['魑', '魅', '魍', '魉'];
    const REVERSE_MAP = { '魑': 0, '魅': 1, '魍': 2, '魉': 3 };
    const SALT_LENGTH = 16;
    const IV_LENGTH = 12;
    const ITERATIONS_BYTES = 4;
    const ENCODER = new TextEncoder();
    const DECODER = new TextDecoder();
    
    // DOM 元素缓存
    const elements = {
        plainIn: document.getElementById('plainIn'),
        cipherOut: document.getElementById('cipherOut'),
        passEnc: document.getElementById('passEnc'),
        iterations: document.getElementById('iterations'),
        cipherIn: document.getElementById('cipherIn'),
        plainOut: document.getElementById('plainOut'),
        passDec: document.getElementById('passDec'),
        status: document.getElementById('status')
    };

    // 事件监听
    document.getElementById('btnEncrypt').addEventListener('click', encrypt);
    document.getElementById('btnDecrypt').addEventListener('click', decrypt);
    document.getElementById('btnEncClear').addEventListener('click', () => {
        elements.plainIn.value = '';
        elements.cipherOut.value = '';
        elements.passEnc.value = '';
    });
    document.getElementById('btnDecClear').addEventListener('click', () => {
        elements.cipherIn.value = '';
        elements.plainOut.value = '';
        elements.passDec.value = '';
    });
    document.getElementById('btnCopyCipher').addEventListener('click', copyCipherText);
    document.getElementById('btnSelfTest').addEventListener('click', selfTest);

    // 自定义字符编码 (Base4)
    function encodeCustom(uint8Array) {
        const chars = [];
        for (const byte of uint8Array) {
            chars.push(
                CHAR_MAP[(byte >> 6) & 0x03],
                CHAR_MAP[(byte >> 4) & 0x03],
                CHAR_MAP[(byte >> 2) & 0x03],
                CHAR_MAP[byte & 0x03]
            );
        }
        return chars.join('');
    }

    function decodeCustom(str) {
        const cleanStr = str.replace(/[^魑魅魍魉]/g, '');
        if (cleanStr.length % 4 !== 0) {
            throw new Error('密文长度无效');
        }
        
        const len = cleanStr.length / 4;
        const uint8Array = new Uint8Array(len);
        
        for (let i = 0; i < len; i++) {
            const idx = i * 4;
            const byte = (REVERSE_MAP[cleanStr[idx]] << 6) |
                        (REVERSE_MAP[cleanStr[idx + 1]] << 4) |
                        (REVERSE_MAP[cleanStr[idx + 2]] << 2) |
                        REVERSE_MAP[cleanStr[idx + 3]];
            uint8Array[i] = byte;
        }
        return uint8Array;
    }

    // 密钥派生
    async function deriveKey(password, salt, iterations) {
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            ENCODER.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt,
                iterations,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // 加密
    async function encrypt() {
        const plainText = elements.plainIn.value.trim();
        const password = elements.passEnc.value;
        const iterations = parseInt(elements.iterations.value, 10);

        if (!plainText) {
            return updateStatus('请输入要加密的明文！');
        }
        if (!password) {
            return updateStatus('请输入口令！');
        }
        if (iterations < 10000) {
            return updateStatus('迭代次数至少为 10000！');
        }

        try {
            // 生成随机盐和IV
            const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
            const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

            // 派生密钥并加密
            const key = await deriveKey(password, salt, iterations);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                ENCODER.encode(plainText)
            );

            // 组合数据：迭代次数(4) + 盐(16) + IV(12) + 密文
            const totalLength = ITERATIONS_BYTES + SALT_LENGTH + IV_LENGTH + encrypted.byteLength;
            const result = new Uint8Array(totalLength);
            const view = new DataView(result.buffer);
            
            view.setUint32(0, iterations, false);
            result.set(salt, ITERATIONS_BYTES);
            result.set(iv, ITERATIONS_BYTES + SALT_LENGTH);
            result.set(new Uint8Array(encrypted), ITERATIONS_BYTES + SALT_LENGTH + IV_LENGTH);

            // 转换为自定义字符集
            elements.cipherOut.value = encodeCustom(result);
            updateStatus('加密成功！');
        } catch (error) {
            updateStatus(`加密失败：${error.message}`);
            console.error('Encryption error:', error);
        }
    }

    // 解密
    async function decrypt() {
        const cipherText = elements.cipherIn.value.trim();
        const password = elements.passDec.value;

        if (!cipherText) {
            return updateStatus('请输入要解密的密文！');
        }
        if (!password) {
            return updateStatus('请输入口令！');
        }

        try {
            // 解码自定义字符集
            const data = decodeCustom(cipherText);
            
            // 检查数据长度
            const minLength = ITERATIONS_BYTES + SALT_LENGTH + IV_LENGTH;
            if (data.length < minLength) {
                throw new Error('密文数据不完整');
            }

            // 提取数据
            const view = new DataView(data.buffer);
            const iterations = view.getUint32(0, false);
            const salt = data.slice(ITERATIONS_BYTES, ITERATIONS_BYTES + SALT_LENGTH);
            const iv = data.slice(ITERATIONS_BYTES + SALT_LENGTH, ITERATIONS_BYTES + SALT_LENGTH + IV_LENGTH);
            const encrypted = data.slice(ITERATIONS_BYTES + SALT_LENGTH + IV_LENGTH);

            // 派生密钥并解密
            const key = await deriveKey(password, salt, iterations);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                encrypted
            );

            // 转换为文本
            elements.plainOut.value = DECODER.decode(decrypted);
            updateStatus('解密成功！');
        } catch (error) {
            updateStatus('解密失败：口令错误或密文已损坏');
            console.error('Decryption error:', error);
        }
    }

    // 复制密文
    async function copyCipherText() {
        const cipherText = elements.cipherOut.value;
        
        if (!cipherText) {
            return updateStatus('没有可复制的密文！');
        }

        try {
            await navigator.clipboard.writeText(cipherText);
            updateStatus('密文已复制到剪贴板！');
        } catch {
            // 降级方案
            elements.cipherOut.select();
            try {
                document.execCommand('copy');
                updateStatus('密文已复制到剪贴板！');
            } catch {
                updateStatus('复制失败，请手动选择并复制');
            }
        }
    }

    // 自检
    async function selfTest() {
        const testText = '测试文本123ABC!@#\n多行测试';
        const testPassword = '测试口令';
        const testIterations = 100000;
        
        try {
            // 设置测试数据
            elements.plainIn.value = testText;
            elements.passEnc.value = testPassword;
            elements.iterations.value = testIterations;
            
            // 加密
            updateStatus('正在运行自检：加密中...');
            await encrypt();
            await sleep(500);
            
            const cipherText = elements.cipherOut.value;
            if (!cipherText) {
                return updateStatus('自检失败：加密未产生密文');
            }
            
            // 解密
            elements.cipherIn.value = cipherText;
            elements.passDec.value = testPassword;
            
            updateStatus('正在运行自检：解密中...');
            await decrypt();
            await sleep(500);
            
            // 验证结果
            const decryptedText = elements.plainOut.value;
            if (decryptedText === testText) {
                updateStatus('✓ 自检通过！加密和解密功能正常工作。');
            } else {
                updateStatus('✗ 自检失败：解密结果与原文不匹配');
            }
        } catch (error) {
            updateStatus(`自检失败：${error.message}`);
            console.error('Self-test error:', error);
        }
    }

    // 工具函数
    function updateStatus(message) {
        elements.status.textContent = message;
    }

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
});