// 使用 AES 加密算法（基于 Web Crypto API）

/**
 * 将字符串转换为 ArrayBuffer
 */
function str2ab(str) {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}

/**
 * 将 ArrayBuffer 转换为字符串
 */
function ab2str(buffer) {
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
}

/**
 * 将 ArrayBuffer 转换为 Base64
 */
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * 将 Base64 转换为 ArrayBuffer
 */
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * 从密码派生密钥
 */
async function deriveKey(password, salt) {
    const passwordBuffer = str2ab(password);
    
    // 导入密码作为密钥材料
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );
    
    // 使用 PBKDF2 派生密钥
    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * 加密函数
 */
async function encryptText(plaintext, password) {
    try {
        // 生成随机盐值
        const salt = crypto.getRandomValues(new Uint8Array(16));
        
        // 派生密钥
        const key = await deriveKey(password, salt);
        
        // 生成随机 IV
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // 加密数据
        const plaintextBuffer = str2ab(plaintext);
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            plaintextBuffer
        );
        
        // 组合 salt + iv + ciphertext
        const resultBuffer = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
        resultBuffer.set(salt, 0);
        resultBuffer.set(iv, salt.length);
        resultBuffer.set(new Uint8Array(ciphertext), salt.length + iv.length);
        
        // 转换为 Base64
        return arrayBufferToBase64(resultBuffer.buffer);
    } catch (error) {
        throw new Error('加密失败: ' + error.message);
    }
}

/**
 * 解密函数
 */
async function decryptText(ciphertext, password) {
    try {
        // 从 Base64 解码
        const dataBuffer = base64ToArrayBuffer(ciphertext);
        const data = new Uint8Array(dataBuffer);
        
        // 提取 salt, iv 和 ciphertext
        const salt = data.slice(0, 16);
        const iv = data.slice(16, 28);
        const encryptedData = data.slice(28);
        
        // 派生密钥
        const key = await deriveKey(password, salt);
        
        // 解密数据
        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encryptedData
        );
        
        // 转换为字符串
        return ab2str(decryptedBuffer);
    } catch (error) {
        throw new Error('解密失败: 口令可能不正确或密文已损坏');
    }
}

/**
 * 加密按钮处理
 */
async function encrypt() {
    const plaintext = document.getElementById('plaintext').value;
    const password = document.getElementById('encryptPassword').value;
    const ciphertextArea = document.getElementById('ciphertext');
    
    if (!plaintext) {
        alert('请输入要加密的明文！');
        return;
    }
    
    if (!password) {
        alert('请输入加密口令！');
        return;
    }
    
    try {
        const encrypted = await encryptText(plaintext, password);
        ciphertextArea.value = encrypted;
        showNotification('加密成功！', 'success');
    } catch (error) {
        alert('加密失败：' + error.message);
    }
}

/**
 * 解密按钮处理
 */
async function decrypt() {
    const ciphertext = document.getElementById('decryptCiphertext').value;
    const password = document.getElementById('decryptPassword').value;
    const decryptedTextArea = document.getElementById('decryptedText');
    
    if (!ciphertext) {
        alert('请输入要解密的密文！');
        return;
    }
    
    if (!password) {
        alert('请输入解密口令！');
        return;
    }
    
    try {
        const decrypted = await decryptText(ciphertext, password);
        decryptedTextArea.value = decrypted;
        showNotification('解密成功！', 'success');
    } catch (error) {
        alert(error.message);
    }
}

/**
 * 复制密文
 */
function copyCiphertext() {
    const ciphertextArea = document.getElementById('ciphertext');
    
    if (!ciphertextArea.value) {
        alert('没有可复制的密文！');
        return;
    }
    
    ciphertextArea.select();
    document.execCommand('copy');
    showNotification('密文已复制到剪贴板！', 'success');
}

/**
 * 切换密码可见性
 */
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    if (field.type === 'password') {
        field.type = 'text';
    } else {
        field.type = 'password';
    }
}

/**
 * 运行自检
 */
async function runSelfTest() {
    const testResultDiv = document.getElementById('testResult');
    testResultDiv.classList.remove('success', 'error');
    testResultDiv.classList.add('show');
    testResultDiv.innerHTML = '<p>🔄 正在运行自检...</p>';
    
    try {
        // 测试数据
        const testPlaintext = '这是一段测试文本，用于验证加密解密功能是否正常。Test 123!@#';
        const testPassword = 'TestPassword123!';
        
        // 测试 1: 基本加密解密
        const encrypted = await encryptText(testPlaintext, testPassword);
        const decrypted = await decryptText(encrypted, testPassword);
        
        if (decrypted !== testPlaintext) {
            throw new Error('加密解密结果不匹配');
        }
        
        // 测试 2: 错误密码
        let errorCaught = false;
        try {
            await decryptText(encrypted, 'WrongPassword');
        } catch (e) {
            errorCaught = true;
        }
        
        if (!errorCaught) {
            throw new Error('错误密码测试失败');
        }
        
        // 测试 3: 多次加密产生不同结果（因为使用随机 IV）
        const encrypted2 = await encryptText(testPlaintext, testPassword);
        if (encrypted === encrypted2) {
            throw new Error('多次加密应产生不同结果');
        }
        
        // 测试 4: 特殊字符
        const specialText = '特殊字符测试：🔐🎉中文English123!@#$%^&*()';
        const encrypted3 = await encryptText(specialText, testPassword);
        const decrypted3 = await decryptText(encrypted3, testPassword);
        
        if (decrypted3 !== specialText) {
            throw new Error('特殊字符加密解密失败');
        }
        
        // 所有测试通过
        testResultDiv.classList.remove('error');
        testResultDiv.classList.add('success');
        testResultDiv.innerHTML = `
            <p><strong>✅ 自检通过！所有测试均成功完成。</strong></p>
            <ul style="margin-top: 10px; margin-left: 20px;">
                <li>✓ 基本加密解密功能正常</li>
                <li>✓ 错误口令正确拒绝</li>
                <li>✓ 随机性验证通过</li>
                <li>✓ 特殊字符处理正常</li>
            </ul>
            <p style="margin-top: 10px;">加密算法：AES-256-GCM | 密钥派生：PBKDF2 (100000 迭代)</p>
        `;
    } catch (error) {
        testResultDiv.classList.remove('success');
        testResultDiv.classList.add('error');
        testResultDiv.innerHTML = `
            <p><strong>❌ 自检失败！</strong></p>
            <p>错误信息：${error.message}</p>
        `;
    }
}

/**
 * 显示通知
 */
function showNotification(message, type) {
    // 简单的通知实现
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? '#28a745' : '#dc3545'};
        color: white;
        padding: 15px 25px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        z-index: 9999;
        animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = message;
    
    // 添加动画
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    `;
    document.head.appendChild(style);
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideIn 0.3s ease-out reverse';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 2000);
}

// 页面加载时的提示
window.addEventListener('load', () => {
    console.log('魑魅魍魉加密系统已就绪');
    console.log('使用 AES-256-GCM 加密算法');
    console.log('PBKDF2 密钥派生（100000 迭代）');
});
