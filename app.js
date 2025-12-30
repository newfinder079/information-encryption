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

        if (!plainText) {
            return updateStatus('请输入要加密的明文！');
        }
        if (!password) {
            return updateStatus('请输入口令！');
        }

        showProcessSection();
        clearProcessSteps();
        addProcessStep('ℹ️ 提示', '加密功能已移除', 'info');
        elements.cipherOut.value = '';
        updateStatus('加密功能已移除');
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

        showProcessSection();
        clearProcessSteps();
        addProcessStep('ℹ️ 提示', '解密功能已移除', 'info');
        elements.plainOut.value = '';
        updateStatus('解密功能已移除');
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
        showProcessSection();
        clearProcessSteps();
        addProcessStep('ℹ️ 提示', '自检功能已移除', 'info');
        updateStatus('自检功能已移除');
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