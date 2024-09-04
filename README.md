# 🔗 ENS Superchain Resolver

Welcome to the **ENS Superchain Resolver** documentation! This project enables scalable and efficient storage and management of ENS records on superchains such as OP Mainnet and Base, while ensuring data integrity through verifiable storage proofs. 🎉

![ENS Superchain Resolver](https://via.placeholder.com/800x200.png?text=ENS+Superchain+Resolver)

## 📑 Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
   - [ENS Superchain Resolver Contract (L1)](#ens-superchain-resolver-contract-l1)
   - [CCIP Gateway Server](#ccip-gateway-server)
   - [ENS Records Smart Contracts (L2)](#ens-records-smart-contracts-l2)
3. [How It Works](#how-it-works)
   - [Step-by-Step Process](#step-by-step-process)
4. [How to Use](#how-to-use)
   - [For End Users](#for-end-users)
   - [For Developers](#for-developers)
5. [Code Snippets](#code-snippets)
   - [Example: Querying the ENS Superchain Resolver](#example-querying-the-ens-superchain-resolver)
   - [Gateway Server Request Handling](#gateway-server-request-handling)
6. [License](#license)

---

## 🔍 Overview

The ENS Superchain Resolver is a next-generation solution for managing ENS records on L2 networks, such as OP Mainnet and Base. It reduces congestion and fees on Ethereum mainnet by securely querying and verifying records stored on L2, using a Cross-Chain Interoperability Protocol (CCIP) for trust-minimized interoperability.

### 🌟 Key Features

- **Scalable and Efficient**: Utilizes L2 networks to minimize congestion and fees.
- **Trust-Minimized**: Provides verifiable storage proofs, ensuring that records returned are authentic and untampered.
- **Compatible with CCIP**: Integrates with the Cross-Chain Interoperability Protocol to facilitate secure cross-chain communication.

![How It Works](https://via.placeholder.com/800x400.png?text=How+ENS+Superchain+Resolver+Works)

## 🏗️ System Architecture

### 🔒 ENS Superchain Resolver Contract (L1)

The **ENS Superchain Resolver Contract** is deployed on Ethereum mainnet (L1) and serves as the ENS resolver for domains. It implements CCIP read to enable secure off-chain lookups.

- **`resolve(bytes calldata name, bytes calldata data)`**: Handles queries by emitting an `OffchainLookup` event to request data from the CCIP Gateway Server.
- **`resolveWithProof(bytes calldata response, bytes calldata extraData)`**: Verifies storage proofs returned by the gateway server and checks them against the state root on Ethereum mainnet.

#### Key Solidity Code 📝

```solidity
contract OP_Resolver is Ownable {
    ENS immutable ens = ENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    INameWrapper immutable nameWrapper = INameWrapper(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401);

    constructor(address initialOwner, string memory _url, address[] memory _signers, address oracle, address registry) Ownable(initialOwner) {
        url = _url;
        DisputeOracle = oracle;
        deployedRegistryOnL2 = registry;
        for (uint i = 0; i < _signers.length; i++) {
            signers[_signers[i]] = true;
        }
        emit NewSigners(_signers);
    }

    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory) {
        (bytes4 functionSelector, bytes memory callDataWithoutSelector, bytes32 node) = decodeData(data);
        address authorized = ens.owner(node);
        if (authorized == address(0)) {
            (authorized, node) = findAuthorizedAddress(name);
        }
        if (authorized == address(nameWrapper)) {
            authorized = nameWrapper.ownerOf(uint256(node));
        }
        (uint256 blockNumber,) = getBlockandRoot();
        bytes memory callData = abi.encode(functionSelector, callDataWithoutSelector, authorized, blockNumber);
        string;
        urls[0] = url;
        revert OffchainLookup(address(this), urls, callData, OP_Resolver.resolveWithProof.selector, callData);
    }
}
```
###  🌐 CCIP Gateway Server
The **CCIP Gateway** Server bridges the L1 resolver and L2 contracts. It handles requests, queries L2 records, generates proofs, and returns data back to the L1 resolver.

#### Example of Request Handling 🛠
️
```javascript
const { Web3 } = require('web3');
const { rlp, bufferToHex } = require('ethereumjs-util');
const web3 = new Web3(""); //rpc

const registry = //registry contract
const abi = //ABI of registry contract
const contract = new web3.eth.Contract(abi, registry);

async function handleAddr(callData, authorized, blockNumber, res) {
    const node = web3.eth.abi.decodeParameter('bytes32', callData);
    const rawresult = await contract.methods.addrAndTimestamp(node, authorized).call({}, blockNumber);
   
    if (rawresult === '0x') {
        return res.send({"data": rawresult});
    }
    
    const decoded = web3.eth.abi.decodeParameters(['bytes', 'uint256'], rawresult);
    const result = decoded[0];
    const encodedResult = web3.eth.abi.encodeParameter('address', result);
    const finalSlot = await calculateCoinAddrSlot(node, 60, authorized); // ETH coin type is 60
    returnProof(encodedResult, finalSlot, blockNumber, res);
}
```
### 🏗️ Recalling the L1 Contract with Proofs
After the gateway server generates the required proofs, the L1 contract is recalled with these proofs to verify the authenticity of the data. This ensures that the L1 contract can validate the records returned by the gateway server using the provided storage proofs.

Here's the Solidity function for resolving with proofs on the L1 contract:

```solidity
function resolveWithProof(bytes calldata response, bytes calldata extraData) external view returns (bytes memory result) {
    bytes memory encodedResult;
    ProofData memory proof;
    bytes32 withdrawalStorageRoot;
    bytes32 latestBlockhash;
    bytes4 functionSelector;
    uint256 blockNumber;
    (functionSelector, , , blockNumber) = abi.decode(extraData, (bytes4, bytes, address, uint256));
    (encodedResult, proof.slotPosition, proof.proofsBlob, proof.stateRoot, withdrawalStorageRoot, latestBlockhash) = abi.decode(response, (bytes, bytes32, bytes, bytes32, bytes32, bytes32));
    
    require(compareOutputRoot(proof.stateRoot, withdrawalStorageRoot, latestBlockhash, blockNumber) == true, "Output root comparison failed");

    if (functionSelector == 0xf1cb7e06 || functionSelector == 0xbc1c58d1) {
        require(getValueFromStateProof(proof.stateRoot, deployedRegistryOnBase, proof.slotPosition, proof.proofsBlob) == keccak256(abi.encodePacked(abi.decode(encodedResult, (bytes)))), "StorageProof Value Mismatch");
        return encodedResult;
    }

    if (functionSelector == 0x3b3b57de) {
        require(getValueFromStateProof(proof.stateRoot, deployedRegistryOnBase, proof.slotPosition, proof.proofsBlob) == keccak256(abi.encodePacked(abi.decode(encodedResult, (address)))), "StorageProof Value Mismatch");
        return encodedResult;
    }

    if (functionSelector == 0x59d1d43c) {
        require(getValueFromStateProof(proof.stateRoot, deployedRegistryOnBase, proof.slotPosition, proof.proofsBlob) == keccak256(abi.encodePacked(abi.decode(encodedResult, (string)))), "StorageProof Value Mismatch");
        return encodedResult;
    }
}

```
This function verifies the proofs received from the gateway server by comparing the state root and storage proof values, ensuring data integrity and trustworthiness before returning the final resolved record.



### 📝 ENS Records Smart Contracts (L2)

These smart contracts are deployed on OP Mainnet and Base to store ENS records. Users interact with these contracts to set or update their ENS records (e.g., address records, content hashes, text records).

## 🚀 How It Works

### Step-by-Step Process 🪜

1. **Deploy ENS Superchain Resolver Contract on L1:**
   - Deployed on Ethereum mainnet, it serves as the ENS resolver for users. The contract implements CCIP read and queries a gateway server.

2. **Deploy CCIP Gateway Server:**
   - The server handles requests from the resolver, queries L2 contracts, and generates storage proofs.

3. **Deploy ENS Records Smart Contracts on L2 Chains:**
   - Smart contracts on OP Mainnet and Base store ENS records.

4. **Querying Process:**
   - The ENS client queries the L1 resolver.
   - The L1 resolver triggers an `OffchainLookup` event.
   - The Gateway Server retrieves the records and storage proofs from L2.
   - The L1 resolver verifies the proofs and returns the verified records.

## 🛠️ How to Use

### 🔧 For End Users

1. **Set the ENS Superchain Resolver as Your Resolver:**
   - Go to your ENS domain management interface and set the ENS Superchain Resolver contract address as your domain resolver.

2. **Interact with the ENS Records Manager App:**
   - Use the app to set or update your address records, content hashes, and text records on supported L2 chains.

### 👩‍💻 For Developers

1. **Integrate with the ENS Superchain Resolver:**
   - Ensure your dApp or client supports CCIP read functionality.
   - Use the `ethers.js` library or any CCIP-enabled client to query the resolver.

2. **Run Your Gateway Server:**
   - Clone the gateway server repository and deploy your own instance.

## 💻 Code Snippets

### Example: Querying the ENS Superchain Resolver with CCIP

This example demonstrates how to use `ethers.js` to query the ENS Superchain Resolver, which includes handling the CCIP process.

```javascript
const { ethers } = require("ethers");

// Connect to Ethereum mainnet
const provider = new ethers.providers.JsonRpcProvider("https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID");

// Resolver contract address
const resolverAddress = "0xYourENSResolverAddress";

// Create a contract instance
const resolverContract = new ethers.Contract(resolverAddress, [
  "function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory)"
], provider);

// Define the ENS name and data to query
const ensName = "example.eth";
const data = "0xYourQueryData";

// Function to handle off-chain lookup via CCIP gateway
async function handleOffchainLookup(sender, urls, callData, callbackFunction, extraData) {
  try {
    // Send the request to the first URL in the list
    const response = await fetch(urls[0], {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: callData })
    });

    // Parse the response from the gateway server
    const responseData = await response.json();
    const result = responseData.data;

    // Call the callback function on the resolver contract with the response
    const finalResult = await resolverContract[callbackFunction](result, extraData);
    console.log("Final Record:", finalResult);
  } catch (error) {
    console.error("Error handling off-chain lookup:", error);
  }
}

// Query the resolver
async function queryResolver() {
  try {
    const result = await resolverContract.resolve(ethers.utils.namehash(ensName), data);
    console.log("Record:", result);
  } catch (error) {
    if (error.errorName === "OffchainLookup") {
      const { sender, urls, callData, callbackFunction, extraData } = error.errorArgs;
      await handleOffchainLookup(sender, urls, callData, callbackFunction, extraData);
    } else {
      console.error("Error querying resolver:", error);
    }
  }
}

queryResolver();
```

### Gateway Server Request Handling

Example of handling a request on the gateway server:

```javascript
async function handleText(callData, authorized, blockNumber, res) {
    const decodedVars = web3.eth.abi.decodeParameters(['bytes32', 'string'], callData);
    const node = decodedVars[0];
    const key = decodedVars[1];
    const rawresult = await contract.methods.textAndTimestamp(node, key, authorized).call({}, blockNumber);

    if (rawresult === '0x') {
        return res.send({"data": rawresult});
    }

    const decoded = web3.eth.abi.decodeParameters(['string', 'uint256'], rawresult);
    const result = decoded[0];
    const encodedResult = web3.eth.abi.encodeParameter('string', result);
    const finalSlot = await calculateTextSlot(node, key, authorized);

    returnProof(encodedResult, finalSlot, blockNumber, res);
}
```

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/WildcardLabs/superchain-resolver/blob/main/LICENSE.txt) file for details.
















