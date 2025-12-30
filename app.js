// app.js

document.addEventListener('DOMContentLoaded', () => {
    // 常量定义
    const CHAR_MAP = [
        '魑', '魅', '魍', '魉', '魃', '魈', '魁', '鬾',
        '魆', '魊', '魋', '魌', '魐', '魒', '魓', '魕',
        '龙', '凤', '麒', '麟', '鲲', '鹏', '貔', '貅',
        '饕', '餮', '梼', '杌', '穷', '奇', '混', '沌',
        '烛', '九', '阴', '白', '泽', '夔', '獬', '豸',
        '天', '狗', '毕', '方', '腾', '蛇', '应', '龙',
        '狴', '犴', '螭', '吻', '朝', '天', '睚', '眦',
        '嘲', '风', '蒲', '牢', '狻', '猊', '赑', '屃'
    ];
    const REVERSE_MAP = {};
    CHAR_MAP.forEach((char, index) => { REVERSE_MAP[char] = index; });
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
    console.log('加密工具已加载');
    document.getElementById('btnEncrypt').addEventListener('click', () => {
        console.log('加密按钮被点击');
        encrypt();
    });
    document.getElementById('btnDecrypt').addEventListener('click', () => {
        console.log('解密按钮被点击');
        decrypt();
    });
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
    document.getElementById('btnSelfTest').addEventListener('click', () => {
        console.log('自检按钮被点击');
        selfTest();
    });

    // 测试编码解码是否正确
    function testEncodeDecode() {
        console.log('=== 测试编码解码 ===');
        const testData = new Uint8Array([1, 2, 3, 4, 5, 10, 20, 30, 40, 50, 100, 150, 200, 250, 255]);
        console.log('原始数据:', Array.from(testData));
        
        const encoded = encodeCustom(testData);
        console.log('编码结果:', encoded, '长度:', encoded.length);
        
        const decoded = decodeCustom(encoded);
        console.log('解码结果:', Array.from(decoded));
        
        let match = testData.length === decoded.length;
        if (match) {
            for (let i = 0; i < testData.length; i++) {
                if (testData[i] !== decoded[i]) {
                    match = false;
                    console.error('不匹配位置:', i, '期望:', testData[i], '实际:', decoded[i]);
                    break;
                }
            }
        } else {
            console.error('长度不匹配:', testData.length, 'vs', decoded.length);
        }
        
        console.log('编码解码测试:', match ? '通过' : '失败');
        return match;
    }
    
    // 运行测试
    testEncodeDecode();

    // 自定义字符编码 (Base64)
    function encodeCustom(uint8Array) {
        const chars = [];
        const len = uint8Array.length;
        
        let i = 0;
        // 每3个字节编码为4个字符
        while (i < len) {
            const b1 = uint8Array[i++];
            const b2 = i < len ? uint8Array[i++] : 0;
            const b3 = i < len ? uint8Array[i++] : 0;
            
            chars.push(
                CHAR_MAP[b1 >> 2],
                CHAR_MAP[((b1 & 0x03) << 4) | (b2 >> 4)],
                CHAR_MAP[((b2 & 0x0F) << 2) | (b3 >> 6)],
                CHAR_MAP[b3 & 0x3F]
            );
        }
        
        // 添加填充标记（根据原始长度）
        const padding = len % 3;
        return chars.join('') + CHAR_MAP[padding];
    }

    function decodeCustom(str) {
        // 过滤出有效字符
        const cleanStr = Array.from(str).filter(c => REVERSE_MAP[c] !== undefined).join('');
        
        if (cleanStr.length < 1) {
            throw new Error('密文为空');
        }
        
        // 读取填充标记（最后一个字符）
        const padding = REVERSE_MAP[cleanStr[cleanStr.length - 1]];
        if (padding > 2) {
            throw new Error('密文格式错误');
        }
        
        const dataStr = cleanStr.slice(0, -1);  // 去除填充标记
        
        if (dataStr.length % 4 !== 0) {
            throw new Error('密文长度无效');
        }
        
        const bytes = [];
        
        // 每4个字符解码为3个字节
        for (let i = 0; i < dataStr.length; i += 4) {
            const c1 = REVERSE_MAP[dataStr[i]];
            const c2 = REVERSE_MAP[dataStr[i + 1]];
            const c3 = REVERSE_MAP[dataStr[i + 2]];
            const c4 = REVERSE_MAP[dataStr[i + 3]];
            
            bytes.push(
                (c1 << 2) | (c2 >> 4),
                ((c2 & 0x0F) << 4) | (c3 >> 2),
                ((c3 & 0x03) << 6) | c4
            );
        }
        
        // 根据填充标记截取正确长度
        const result = new Uint8Array(bytes);
        if (padding === 0) {
            return result;
        } else {
            // padding=1表示原始长度%3=1，需要保留...+1个字节
            // padding=2表示原始长度%3=2，需要保留...+2个字节
            const correctLength = Math.floor(result.length / 3) * 3 + padding;
            return result.slice(0, correctLength);
        }
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
        const plainText = elements.plainIn.value;
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
            // 显示过程
            showProcessSection();
            clearProcessSteps();
            
            const plainBytes = ENCODER.encode(plainText);
            addProcessStep('📝 步骤 1: 读取输入', `明文: ${plainText.length} 字符 (${plainBytes.length} 字节)\n迭代次数: ${iterations.toLocaleString()}`);
            
            // 生成随机盐和IV
            addProcessStep('🎲 步骤 2: 生成随机数', `生成盐值和初始化向量...`);
            const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
            const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
            addProcessStep('✓ 随机数生成完成', `盐值: ${formatBytes(salt)}\nIV: ${formatBytes(iv)}`, 'success');

            // 派生密钥
            addProcessStep('🔑 步骤 3: 密钥派生', `使用 PBKDF2-SHA256 (${iterations.toLocaleString()} 次迭代)...`);
            const key = await deriveKey(password, salt, iterations);
            addProcessStep('✓ 密钥派生完成', `AES-256 密钥已生成`, 'success');
            
            // 加密数据
            addProcessStep('🔐 步骤 4: AES-GCM 加密', `加密 ${plainBytes.length} 字节数据...`);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                plainBytes
            );
            addProcessStep('✓ 加密完成', `密文: ${encrypted.byteLength} 字节`, 'success');

            // 组合数据：迭代次数(4) + 盐(16) + IV(12) + 密文
            addProcessStep('📦 步骤 5: 组合数据', `打包所有组件...`);
            const result = new Uint8Array(ITERATIONS_BYTES + SALT_LENGTH + IV_LENGTH + encrypted.byteLength);
            const view = new DataView(result.buffer);
            
            let offset = 0;
            view.setUint32(offset, iterations, false);
            offset += ITERATIONS_BYTES;
            result.set(salt, offset);
            offset += SALT_LENGTH;
            result.set(iv, offset);
            offset += IV_LENGTH;
            result.set(new Uint8Array(encrypted), offset);
            
            addProcessStep('✓ 数据组合完成', `总计: ${result.length} 字节`, 'success');

            // 转换为自定义字符集
            addProcessStep('🔤 步骤 6: 编码', `Base64编码为神兽汉字...`);
            const encoded = encodeCustom(result);
            addProcessStep('✓ 编码完成', `最终密文: ${encoded.length} 个字符`, 'success');
            
            elements.cipherOut.value = encoded;
            updateStatus('✓ 加密成功！');
        } catch (error) {
            addProcessStep('✗ 错误', error.message, 'error');
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
            // 显示过程
            showProcessSection();
            clearProcessSteps();
            addProcessStep('📝 步骤 1: 读取密文', `密文: ${cipherText.length} 个字符`);
            
            // 解码自定义字符集
            addProcessStep('🔤 步骤 2: 解码', `将神兽汉字解码为二进制...`);
            const data = decodeCustom(cipherText);
            addProcessStep('✓ 解码完成', `二进制数据: ${data.length} 字节`, 'success');
            
            // 检查数据长度
            const minLength = ITERATIONS_BYTES + SALT_LENGTH + IV_LENGTH;
            if (data.length < minLength) {
                throw new Error('密文数据不完整');
            }

            // 提取数据
            addProcessStep('📦 步骤 3: 提取数据', `分离各个组件...`);
            const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
            
            let offset = 0;
            const iterations = view.getUint32(offset, false);
            offset += ITERATIONS_BYTES;
            
            const salt = data.slice(offset, offset + SALT_LENGTH);
            offset += SALT_LENGTH;
            
            const iv = data.slice(offset, offset + IV_LENGTH);
            offset += IV_LENGTH;
            
            const encrypted = data.slice(offset);
            
            addProcessStep('✓ 数据提取完成', `迭代: ${iterations.toLocaleString()}\n盐: ${formatBytes(salt, 24)}\nIV: ${formatBytes(iv, 24)}\n密文: ${encrypted.length} 字节`, 'success');

            // 派生密钥
            addProcessStep('🔑 步骤 4: 密钥派生', `使用 PBKDF2-SHA256 (${iterations.toLocaleString()} 次迭代)...`);
            const key = await deriveKey(password, salt, iterations);
            addProcessStep('✓ 密钥派生完成', `AES-256 密钥已生成`, 'success');
            
            // 解密
            addProcessStep('🔓 步骤 5: AES-GCM 解密', `解密 ${encrypted.length} 字节数据...`);
            let decrypted;
            try {
                decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv },
                    key,
                    encrypted
                );
                addProcessStep('✓ 解密完成', `明文: ${decrypted.byteLength} 字节`, 'success');
            } catch (decryptError) {
                addProcessStep('✗ 解密失败', `口令错误！无法通过AES-GCM验证。`, 'error');
                throw new Error('口令错误');
            }

            // 转换为文本
            addProcessStep('📄 步骤 6: 文本解码', `UTF-8解码...`);
            const plainText = DECODER.decode(decrypted);
            addProcessStep('✓ 解码完成', `${plainText.length} 个字符`, 'success');
            
            elements.plainOut.value = plainText;
            updateStatus('✓ 解密成功！');
        } catch (error) {
            if (!error.message.includes('口令错误') && !error.message.includes('密文')) {
                addProcessStep('✗ 错误', error.message, 'error');
            }
            updateStatus(`解密失败：${error.message}`);
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
            // 规范化换行符进行比较（Windows下textarea可能使用\r\n）
            const normalizedTest = testText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
            const normalizedDecrypted = decryptedText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
            
            console.log('原始文本:', JSON.stringify(testText));
            console.log('解密文本:', JSON.stringify(decryptedText));
            console.log('规范化后原始:', JSON.stringify(normalizedTest));
            console.log('规范化后解密:', JSON.stringify(normalizedDecrypted));
            console.log('长度对比:', normalizedTest.length, 'vs', normalizedDecrypted.length);
            console.log('是否相等:', normalizedDecrypted === normalizedTest);
            
            if (normalizedDecrypted === normalizedTest) {
                updateStatus('✓ 自检通过！加密和解密功能正常工作。');
            } else {
                updateStatus('✗ 自检失败：解密结果与原文不匹配');
                console.error('字符对比:');
                for (let i = 0; i < Math.max(normalizedTest.length, normalizedDecrypted.length); i++) {
                    if (normalizedTest[i] !== normalizedDecrypted[i]) {
                        console.error(`位置${i}: 期望 "${normalizedTest[i]}" (${normalizedTest.charCodeAt(i)}), 实际 "${normalizedDecrypted[i]}" (${normalizedDecrypted.charCodeAt(i)})`);
                    }
                }
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

    // 过程展示相关函数
    function showProcessSection() {
        document.getElementById('processSection').style.display = 'block';
    }

    function hideProcessSection() {
        document.getElementById('processSection').style.display = 'none';
    }

    function clearProcessSteps() {
        document.getElementById('processSteps').innerHTML = '';
    }

    function addProcessStep(title, detail, type = 'info') {
        const stepsDiv = document.getElementById('processSteps');
        const stepDiv = document.createElement('div');
        stepDiv.className = `process-step ${type}`;
        
        const titleDiv = document.createElement('div');
        titleDiv.className = 'step-title';
        titleDiv.textContent = title;
        
        const detailDiv = document.createElement('div');
        detailDiv.className = 'step-detail';
        detailDiv.textContent = detail;
        
        stepDiv.appendChild(titleDiv);
        if (detail) stepDiv.appendChild(detailDiv);
        stepsDiv.appendChild(stepDiv);
        
        // 自动滚动到底部
        stepsDiv.scrollTop = stepsDiv.scrollHeight;
    }

    function formatBytes(bytes, maxLen = 32) {
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        return hex.length > maxLen ? hex.substring(0, maxLen) + '...' : hex;
    }
});