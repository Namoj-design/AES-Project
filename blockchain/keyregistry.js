// blockchain/keyregistry.js
// Handles ECDH public key registration, retrieval, and on-chain verification.
// Works together with web3.js and identity.sol.

import { ethers } from "https://cdn.jsdelivr.net/npm/ethers@6.8.0/+esm";
import { connectWallet } from "./web3.js";

/* ------------------ Contract Configuration ------------------ */
const CONTRACT_ADDRESS = "0xYourDeployedContract"; // Replace with deployed address
const ABI = [
  "function registerKey(bytes pubKey)",
  "function getKey(address user) view returns (bytes32)",
  "event KeyRegistered(address indexed user, bytes32 fingerprint, uint256 time)"
];

/* ------------------ Core Registry Functions ------------------ */

/**
 * Register the user's ECDH public key on-chain.
 * @param {string} pubKeyB64 - The base64 encoded ECDH public key (from WebCrypto export)
 */
export async function registerECDHKey(pubKeyB64) {
  try {
    const { signer, address } = await connectWallet();
    const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer);

    // Convert base64 → bytes
    const raw = Uint8Array.from(atob(pubKeyB64), c => c.charCodeAt(0));

    console.log("Registering key for", address);
    const tx = await contract.registerKey(raw);
    await tx.wait();

    console.log("✅ Key successfully registered on-chain!");
    return address;
  } catch (err) {
    console.error("❌ Registration failed:", err.message);
    throw err;
  }
}

/**
 * Verify if a given base64 public key matches the one registered on-chain.
 * @param {string} pubKeyB64 - Local ECDH public key (from WebCrypto)
 * @param {string} userAddress - Ethereum address of the peer
 * @returns {boolean} true if the key is verified
 */
export async function verifyOnChainKey(pubKeyB64, userAddress) {
  try {
    const { provider } = await connectWallet();
    const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

    const fingerprintOnChain = await contract.getKey(userAddress);
    if (!fingerprintOnChain || fingerprintOnChain === ethers.ZeroHash) {
      console.warn("No key registered on-chain for this address.");
      return false;
    }

    // Locally hash the provided pubKeyB64
    const raw = Uint8Array.from(atob(pubKeyB64), c => c.charCodeAt(0));
    const localHashBuffer = await crypto.subtle.digest("SHA-256", raw);
    const localHash = "0x" + Array.from(new Uint8Array(localHashBuffer))
      .map(b => b.toString(16).padStart(2, "0")).join("");

    console.log("Local fingerprint:", localHash);
    console.log("On-chain fingerprint:", fingerprintOnChain);

    return fingerprintOnChain.toLowerCase() === localHash.toLowerCase();
  } catch (err) {
    console.error("Verification failed:", err.message);
    return false;
  }
}

/**
 * Fetch the current fingerprint for a user from the blockchain.
 * @param {string} address - Ethereum address
 * @returns {string} bytes32 fingerprint hex
 */
export async function getFingerprint(address) {
  const { provider } = await connectWallet();
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);
  return await contract.getKey(address);
}