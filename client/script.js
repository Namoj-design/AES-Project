const enc = new TextEncoder();
const dec = new TextDecoder();
const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

/* ----- Crypto helpers ----- */
async function genECDH(){return crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveKey"]);}
async function exportPub(k){return toB64(await crypto.subtle.exportKey("raw",k));}
async function importPub(b64){return crypto.subtle.importKey("raw",fromB64(b64).buffer,{name:"ECDH",namedCurve:"P-256"},true,[]);}
async function deriveAES(priv, pub){
  return crypto.subtle.deriveKey({name:"ECDH",public:pub},priv,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
function randIV(){const v=new Uint8Array(12);crypto.getRandomValues(v);return v;}
async function aesEnc(key, msg){
  const iv=randIV();
  const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(msg));
  return {iv:toB64(iv.buffer), ct:toB64(ct)};
}
async function aesDec(key, ivB64, ctB64){
  const iv=fromB64(ivB64);const ct=fromB64(ctB64);
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct.buffer);
  return dec.decode(pt);
}

/* ----- State ----- */
let alice={}; let bob={};

/* ----- UI helper for bubbles ----- */
function appendBubble(whoPanel, who, text){
  const box=document.getElementById(whoPanel+"-chat");
  const b=document.createElement("div");
  b.className="bubble "+who;
  b.textContent=text;
  box.appendChild(b);
  box.scrollTop=box.scrollHeight;
}

/* ----- Alice actions ----- */
document.getElementById("alice-gen").onclick=async()=>{
  alice.keys=await genECDH();
  document.getElementById("alice-pub").value=await exportPub(alice.keys.publicKey);
  alert("Alice keypair ready. Copy her public key into Bob's box.");
};
document.getElementById("alice-derive").onclick=async()=>{
  const peer=document.getElementById("alice-peer").value.trim();
  const pub=await importPub(peer);
  alice.aes=await deriveAES(alice.keys.privateKey,pub);
  alert("Alice derived AES key.");
};
document.getElementById("alice-send").onclick=async()=>{
  const msg=document.getElementById("alice-input").value.trim();
  if(!msg||!alice.aes) return;
  const {iv,ct}=await aesEnc(alice.aes,msg);
  const payload=iv+"|"+ct;
  document.getElementById("bob-recvbuf").value=payload; // hidden buffer
  appendBubble("alice","alice",msg);
  appendBubble("bob","alice","(encrypted msg received)");
  document.getElementById("alice-input").value="";
};

/* ----- Bob actions ----- */
document.getElementById("bob-gen").onclick=async()=>{
  bob.keys=await genECDH();
  document.getElementById("bob-pub").value=await exportPub(bob.keys.publicKey);
  alert("Bob keypair ready. Copy his public key into Alice's box.");
};
document.getElementById("bob-derive").onclick=async()=>{
  const peer=document.getElementById("bob-peer").value.trim();
  const pub=await importPub(peer);
  bob.aes=await deriveAES(bob.keys.privateKey,pub);
  alert("Bob derived AES key.");
};
document.getElementById("bob-send").onclick=async()=>{
  const msg=document.getElementById("bob-input").value.trim();
  if(!msg||!bob.aes) return;
  const {iv,ct}=await aesEnc(bob.aes,msg);
  const payload=iv+"|"+ct;
  document.getElementById("alice-recvbuf").value=payload;
  appendBubble("bob","bob",msg);
  appendBubble("alice","bob","(encrypted msg received)");
  document.getElementById("bob-input").value="";
};

/* ----- Hidden buffers for local transfer ----- */
["alice","bob"].forEach(side=>{
  const hidden=document.createElement("textarea");
  hidden.id=side+"-recvbuf";
  hidden.style.display="none";
  document.body.appendChild(hidden);
});

/* ----- Auto-decrypt simulation ----- */
setInterval(async()=>{
  // Alice decrypt incoming
  if(alice.aes){
    const data=document.getElementById("alice-recvbuf").value;
    if(data){
      const [iv,ct]=data.split("|");
      try{
        const msg=await aesDec(alice.aes,iv,ct);
        appendBubble("alice","bob",msg);
      }catch{}
      document.getElementById("alice-recvbuf").value="";
    }
  }
  // Bob decrypt incoming
  if(bob.aes){
    const data=document.getElementById("bob-recvbuf").value;
    if(data){
      const [iv,ct]=data.split("|");
      try{
        const msg=await aesDec(bob.aes,iv,ct);
        appendBubble("bob","alice",msg);
      }catch{}
      document.getElementById("bob-recvbuf").value="";
    }
  }
},600);