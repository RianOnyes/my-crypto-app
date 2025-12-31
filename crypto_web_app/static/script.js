// Tab Switching Logic
function openTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    
    document.getElementById(tabId).classList.add('active');
    event.currentTarget.classList.add('active');
}

// 1. Generate Keys
async function generateKeys() {
    const btn = document.querySelector('button[onclick="generateKeys()"]');
    btn.innerText = "Generating...";
    
    const response = await fetch('/api/generate_keys', { method: 'POST' });
    const data = await response.json();
    
    document.getElementById('gen_priv').value = data.private_key;
    document.getElementById('gen_pub').value = data.public_key;
    btn.innerText = "Generate New Key Pair";
}

// 2. Encrypt
async function encryptMsg() {
    const pubKey = document.getElementById('enc_pub_key').value;
    const msg = document.getElementById('enc_msg').value;
    
    if(!pubKey || !msg) return alert("Isi Public Key dan Pesan!");

    const response = await fetch('/api/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ public_key: pubKey, message: msg })
    });
    
    const data = await response.json();
    
    if(data.status === 'success') {
        document.getElementById('enc_result').style.display = 'block';
        document.getElementById('out_aes_key').value = data.enc_aes_key;
        document.getElementById('out_cipher').value = data.ciphertext;
    } else {
        alert("Error: " + data.message);
    }
}

// 3. Decrypt
async function decryptMsg() {
    const privKey = document.getElementById('dec_priv_key').value;
    const aesKey = document.getElementById('in_aes_key').value;
    const cipher = document.getElementById('in_cipher').value;

    if(!privKey || !aesKey || !cipher) return alert("Lengkapi semua data!");

    const response = await fetch('/api/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            private_key: privKey, 
            enc_aes_key: aesKey, 
            ciphertext: cipher 
        })
    });
    
    const data = await response.json();
    
    const resBox = document.getElementById('dec_result_box');
    const resText = document.getElementById('final_text');
    
    resBox.style.display = 'block';
    
    if(data.status === 'success') {
        resText.innerText = data.plaintext;
        resText.style.color = "var(--success)";
    } else {
        resText.innerText = data.message;
        resText.style.color = "var(--danger)";
    }
}