// blockchain/web3.js
import { ethers } from "https://cdn.jsdelivr.net/npm/ethers@6.8.0/+esm";

const CONTRACT_ADDRESS = "0xYourDeployedContract";
const ABI = [
  "function registerKey(bytes pubKey)",
  "function getKey(address) view returns (bytes32)"
];

export async function connectWallet() {
  if (!window.ethereum) throw new Error("MetaMask not found");
  const provider = new ethers.BrowserProvider(window.ethereum);
  const signer = await provider.getSigner();
  const address = await signer.getAddress();
  return { provider, signer, address };
}

export async function registerECDHKey(pubKeyB64) {
  const { signer, address } = await connectWallet();
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer);
  const tx = await contract.registerKey(ethers.getBytes("0x" + atob(pubKeyB64)));
  await tx.wait();
  return address;
}

export async function getRegisteredKey(address) {
  const { provider } = await connectWallet();
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);
  const fingerprint = await contract.getKey(address);
  return fingerprint;
}