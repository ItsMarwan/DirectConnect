
const stateLanding = document.getElementById('state-landing');
const stateSender = document.getElementById('state-sender');
const stateDecrypt = document.getElementById('state-decrypt');
const stateDownload = document.getElementById('state-download');
const stateProgress = document.getElementById('state-progress');
const stateError = document.getElementById('state-error');

const senderPrompt = document.getElementById('sender-prompt');
const senderActive = document.getElementById('sender-active');
const senderPassword = document.getElementById('sender-password');
const senderDecryptBtn = document.getElementById('sender-decrypt-btn');
const senderDecryptError = document.getElementById('sender-decrypt-error');
const senderFileName = document.getElementById('sender-file-name');
const senderFileSize = document.getElementById('sender-file-size');
const shareUrlInput = document.getElementById('share-url-input');
const copyUrlBtn = document.getElementById('copy-url-btn');

const decryptForm = document.getElementById('decrypt-form');
const passwordInput = document.getElementById('password');
const decryptError = document.getElementById('decrypt-error');

const fileNameEl = document.getElementById('file-name');
const fileSizeEl = document.getElementById('file-size');
const connStatusEl = document.getElementById('conn-status');
const fileIconEl = document.getElementById('file-icon');
const downloadBtn = document.getElementById('download-btn');

const progressBar = document.getElementById('progress-bar');
const progressText = document.getElementById('progress-text');

const errorTitle = document.getElementById('error-title');
const errorDesc = document.getElementById('error-desc');

const CHUNK_SIZE = 16384 * 2; 
let decryptedConfig = null;
let myPeer = null;
let activeConnection = null;
let fileBlob = null; 

function showState(element) {
    [stateLanding, stateSender, stateDecrypt, stateDownload, stateProgress, stateError].forEach(el => el.classList.add('hidden'));
    element.classList.remove('hidden');
}

function sha256(str) {
    const buffer = new TextEncoder("utf-8").encode(str);
    return crypto.subtle.digest("SHA-256", buffer);
}

async function deriveKey(password, salt) {
    const saltedPassword = password + salt;
    const hashBuffer = await sha256(saltedPassword);
    return new Uint8Array(hashBuffer);
}

async function decryptPayload(payload, password) {
    try {
        const salt = payload.substring(0, 8);
        const base64Data = payload.substring(8);
        const cleanB64 = base64Data.replace(/-/g, '+').replace(/_/g, '/');
        const encryptedBytes = Uint8Array.from(atob(cleanB64), c => c.charCodeAt(0));
        
        const key = await deriveKey(password, salt);
        const decryptedBytes = new Uint8Array(encryptedBytes.length);
        
        for (let i = 0; i < encryptedBytes.length; i++) {
            const indexBytes = new Uint8Array(4);
            const view = new DataView(indexBytes.buffer);
            view.setUint32(0, i, false);
            
            const block = new Uint8Array(key.length + 4);
            block.set(key);
            block.set(indexBytes, key.length);
            
            const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", block));
            const keystreamByte = hash[0];
            
            decryptedBytes[i] = encryptedBytes[i] ^ keystreamByte;
        }
        
        const jsonStr = new TextDecoder().decode(decryptedBytes);
        return JSON.parse(jsonStr);
    } catch (err) {
        console.error("Payload decryption error:", err);
        return null;
    }
}

async function encryptPayload(dataStr, password) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let salt = '';
    for (let i = 0; i < 8; i++) salt += chars.charAt(Math.floor(Math.random() * chars.length));
    
    const key = await deriveKey(password, salt);
    const dataBytes = new TextEncoder().encode(dataStr);
    const encryptedBytes = new Uint8Array(dataBytes.length);
    
    for (let i = 0; i < dataBytes.length; i++) {
        const indexBytes = new Uint8Array(4);
        const view = new DataView(indexBytes.buffer);
        view.setUint32(0, i, false);
        
        const block = new Uint8Array(key.length + 4);
        block.set(key);
        block.set(indexBytes, key.length);
        
        const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", block));
        const keystreamByte = hash[0];
        
        encryptedBytes[i] = dataBytes[i] ^ keystreamByte;
    }
    
    const base64Data = btoa(String.fromCharCode.apply(null, encryptedBytes))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return salt + base64Data;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getFileIcon(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const archive = ['zip', 'rar', '7z', 'tar', 'gz'];
    const doc = ['pdf', 'doc', 'docx', 'txt', 'rtf'];
    const img = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'];
    const media = ['mp4', 'mkv', 'avi', 'mp3', 'wav'];

    if (archive.includes(ext)) return 'fa-file-zipper';
    if (doc.includes(ext)) return 'fa-file-pdf';
    if (img.includes(ext)) return 'fa-file-image';
    if (media.includes(ext)) return 'fa-file-video';
    return 'fa-file-arrow-down';
}

window.addEventListener('load', () => {
    const hash = window.location.hash.substring(1);
    if (!hash) {
        showState(stateLanding);
        return;
    }

    if (hash.startsWith('sender?p=')) {
        showState(stateSender);
        senderPassword.focus();
    } else {
        showState(stateDecrypt);
        passwordInput.focus();
    }
});

copyUrlBtn.addEventListener('click', () => {
    shareUrlInput.select();
    document.execCommand('copy');
    const origHTML = copyUrlBtn.innerHTML;
    copyUrlBtn.innerHTML = '<i class="fa-solid fa-check text-green-500"></i>';
    setTimeout(() => { copyUrlBtn.innerHTML = origHTML; }, 2000);
});

senderDecryptBtn.addEventListener('click', async () => {
    senderDecryptError.classList.add('hidden');
    const pwd = senderPassword.value;
    if (!pwd) return;

    const urlParams = new URLSearchParams(window.location.hash.split('?')[1]);
    const encryptedPayload = urlParams.get('p');
    
    const localConfig = await decryptPayload(encryptedPayload, pwd);
    if (localConfig && localConfig.port && localConfig.token) {
        senderPrompt.classList.add('hidden');
        senderActive.classList.remove('hidden');
        
        senderFileName.textContent = localConfig.filename;
        senderFileSize.textContent = formatBytes(localConfig.size);

        try {
            const localFileUrl = `http://127.0.0.1:${localConfig.port}/${localConfig.token}`;
            const response = await fetch(localFileUrl);
            if (!response.ok) throw new Error("Local host unresponsive");
            fileBlob = await response.blob();
            initializeWebRTCSender(pwd, localConfig.filename, localConfig.size);
        } catch (e) {
            console.error(e);
            alert("Error: Could not retrieve file locally. Keep DirectConnect.exe alive.");
        }
    } else {
        senderDecryptError.classList.remove('hidden');
    }
});

function initializeWebRTCSender(password, filename, size) {
    myPeer = new Peer({
        config: {
            'iceServers': [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        }
    });

    myPeer.on('open', async (id) => {
        const payloadObject = {
            peerId: id,
            filename: filename,
            size: size
        };
        
        const encShareHash = await encryptPayload(JSON.stringify(payloadObject), password);
        const cleanBaseUrl = window.location.href.split('#')[0];
        shareUrlInput.value = `${cleanBaseUrl}#${encShareHash}`;
        
        const statusIcon = document.getElementById('sender-status-icon');
        const statusText = document.getElementById('sender-status-text');
        statusIcon.className = "h-2.5 w-2.5 bg-green-500 rounded-full animate-pulse";
        statusText.textContent = "Broker registered! Share the URL below.";
    });

    myPeer.on('connection', (conn) => {
        activeConnection = conn;
        
        const statusText = document.getElementById('sender-status-text');
        statusText.innerHTML = `<span class="text-green-500 font-mono text-[11px] uppercase tracking-wide">Transfer Active: Sending directly...</span>`;
        
        conn.on('data', (data) => {
            if (data.type === 'request-meta') {
                conn.send({ type: 'meta', filename: filename, size: size });
            } else if (data.type === 'start') {
                streamFileToPeer(conn);
            }
        });
    });

    myPeer.on('error', (err) => {
        console.error("PeerJS registration error:", err);
        alert("Signaling gateway error. Please try refreshing.");
    });
}

function streamFileToPeer(conn) {
    let offset = 0;
    const totalBytes = fileBlob.size;

    function sendNextBlock() {
        if (offset >= totalBytes) {
            conn.send({ type: 'done' });
            const statusText = document.getElementById('sender-status-text');
            statusText.innerHTML = `<span class="text-green-500 font-mono text-[11px] uppercase tracking-wide font-bold"><i class="fa-solid fa-circle-check"></i> Transfer Completed!</span>`;
            return;
        }

        const slice = fileBlob.slice(offset, offset + CHUNK_SIZE);
        const reader = new FileReader();
        reader.onload = function(event) {
            conn.send({
                type: 'chunk',
                offset: offset,
                data: event.target.result
            });
            offset += CHUNK_SIZE;
        };
        reader.readAsArrayBuffer(slice);
    }

    conn.on('data', (msg) => {
        if (msg.type === 'ack') {
            sendNextBlock();
        }
    });

    sendNextBlock();
}

decryptForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    decryptError.classList.add('hidden');
    
    const pwd = passwordInput.value;
    const hash = window.location.hash.substring(1);

    if (!pwd || !hash) return;

    decryptedConfig = await decryptPayload(hash, pwd);

    if (decryptedConfig && decryptedConfig.peerId) {
        fileNameEl.textContent = decryptedConfig.filename;
        fileSizeEl.textContent = formatBytes(decryptedConfig.size);
        
        const iconClass = getFileIcon(decryptedConfig.filename);
        fileIconEl.className = `fa-solid ${iconClass} text-xl`;

        showState(stateDownload);
        connectToHostPeer(decryptedConfig.peerId);
    } else {
        decryptError.classList.remove('hidden');
        passwordInput.value = '';
        passwordInput.focus();
    }
});

function connectToHostPeer(targetPeerId) {
    myPeer = new Peer({
        config: {
            'iceServers': [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        }
    });

    myPeer.on('open', () => {
        connStatusEl.textContent = "Handshaking secure tunnel route...";
        const conn = myPeer.connect(targetPeerId);
        activeConnection = conn;

        conn.on('open', () => {
            connStatusEl.textContent = "Direct global P2P Tunnel secured.";
            downloadBtn.disabled = false;
            downloadBtn.innerHTML = `<i class="fa-solid fa-download mr-1"></i> Download File Now`;
            downloadBtn.className = "w-full bg-green-600 hover:bg-green-500 text-black font-bold uppercase tracking-wider py-3.5 rounded shadow-lg cursor-pointer transition-all flex items-center justify-center gap-2";
        });

        conn.on('error', (err) => {
            console.error("Connection error:", err);
            showConnectionError();
        });

        conn.on('close', () => {
            console.log("Connection closed.");
        });
    });

    myPeer.on('error', (err) => {
        console.error("Peer registration error:", err);
        showConnectionError();
    });
}

function showConnectionError() {
    errorTitle.textContent = "Tunnel Broken";
    errorDesc.textContent = "Could not initialize link. Verify host node is running with a solid global WebRTC/STUN configuration.";
    showState(stateError);
}

downloadBtn.addEventListener('click', () => {
    if (!activeConnection) return;

    showState(stateProgress);
    progressBar.style.width = '0%';
    progressText.textContent = '0%';

    const totalSize = decryptedConfig.size;
    let receivedChunks = [];
    let currentSize = 0;

    activeConnection.on('data', (msg) => {
        if (msg.type === 'chunk') {
            receivedChunks.push(msg.data);
            currentSize += msg.data.byteLength;
            
            const percent = Math.round((currentSize / totalSize) * 100);
            progressBar.style.width = `${percent}%`;
            progressText.textContent = `${percent}% (${formatBytes(currentSize)} / ${formatBytes(totalSize)})`;

            activeConnection.send({ type: 'ack', offset: msg.offset });
        } else if (msg.type === 'done') {
            const fileBlob = new Blob(receivedChunks, { type: 'application/octet-stream' });
            const blobUrl = URL.createObjectURL(fileBlob);

            const a = document.createElement('a');
            a.href = blobUrl;
            a.download = decryptedConfig.filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(blobUrl);

            activeConnection.close();
            myPeer.destroy();
            
            setTimeout(() => {
                window.location.hash = '';
                window.location.reload();
            }, 2000);
        }
    });

    activeConnection.send({ type: 'start' });
});
