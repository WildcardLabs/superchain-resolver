const { Web3 } = require('web3');
const { rlp, bufferToHex } = require('ethereumjs-util');

const web3 = new Web3(process.env.RPC);

const withdrawal = process.env.L2ToL1MessagePasser;
const registry = process.env.REGISTRY;
const abi = [
  {"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"uint256","name":"coinType","type":"uint256"},{"internalType":"address","name":"owner","type":"address"}],"name":"addr","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"}],"name":"addr","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"address","name":"owner","type":"address"}],"name":"contenthash","outputs":[{"internalType":"bytes","name":"","type":"bytes"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"},{"internalType":"string","name":"key","type":"string"},{"internalType":"address","name":"owner","type":"address"}],"name":"text","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"}
  ];
const contract = new web3.eth.Contract(abi, registry);

exports.gateway = async (req, res) => {

res.set('Access-Control-Allow-Origin', '*');
  
if (req.method === 'OPTIONS') {
    // Send response to OPTIONS requests
    res.set('Access-Control-Allow-Methods', '*');
    res.set('Access-Control-Allow-Headers', '*');
    res.status(204).send('');
  } 
  
else{

    try {
        const { functionSelector, callDataWithoutSelector, authorized, block } = decodeData(req.body);
        processRequest(functionSelector, callDataWithoutSelector, authorized, block, res);
    } 
    catch (error) {
        console.error("Error:", error);
        res.status(500).send("Internal Server Error");
    }
};
}

function decodeData(body) {
    var data;
    if (typeof body == 'object'){
        data = body.data;
    }
    else{
        data = JSON.parse(body).data;
    }
    const decoded = web3.eth.abi.decodeParameters(['bytes4', 'bytes', 'address', 'uint256'], data);
    return {
        functionSelector: decoded[0],
        callDataWithoutSelector: decoded[1],
        authorized: decoded[2].toString(),
        block: Number(decoded[3])
    };
}

async function processRequest(functionSelector, callData, authorized, blockNumber, res) {
        if      (functionSelector == '0x3b3b57de') {
                   handleAddr(callData, authorized, blockNumber, res);
        }
        else if (functionSelector == '0xf1cb7e06') {
                   handleCoinAddr(callData, authorized, blockNumber, res);
        }
        else if (functionSelector == '0x59d1d43c') {
                   handleText(callData, authorized, blockNumber, res);
        }
        else if (functionSelector == '0xbc1c58d1') {
                   handleContent(callData, authorized, blockNumber, res);
        }
        else {
            return res.status(404).send("Record Not Supported");
        }
}



async function handleAddr(callData, authorized, blockNumber, res) {
   
    const node = web3.eth.abi.decodeParameter('bytes32', callData);

    const result = await contract.methods.addr(node, authorized).call({},blockNumber);
    if (result == '0x0000000000000000000000000000000000000000'){
       return res.send({"data": result});
    }
    
    const encodedResult = web3.eth.abi.encodeParameter('address', result);

    const finalSlot = await calculateCoinAddrSlot(node, 60, authorized);

    const proof = await web3.eth.getProof(registry, [finalSlot], blockNumber);
    const hexProof = rlpEncodeProofs([proof.accountProof, proof.storageProof[0].proof]);

    const returndata = await encodeReturnData(encodedResult, finalSlot, hexProof, blockNumber);
    res.send({"data": returndata});
}

async function handleCoinAddr(callData, authorized, blockNumber, res) {

    const decodedVars = web3.eth.abi.decodeParameters(['bytes32', 'uint256'], callData);
    const node = decodedVars[0];
    const coinType = Number(decodedVars[1]);

    const result = await contract.methods.addr(node, coinType, authorized).call({},blockNumber);
    if (result == '0x'){
       return res.send({"data": result});
    }
    
    const encodedResult = web3.eth.abi.encodeParameter('bytes', result);

    const finalSlot = await calculateCoinAddrSlot(node, coinType, authorized);

    const proof = await web3.eth.getProof(registry, [finalSlot], blockNumber);
    const hexProof = rlpEncodeProofs([proof.accountProof, proof.storageProof[0].proof]);
    
    const returndata = await encodeReturnData(encodedResult, finalSlot, hexProof, blockNumber);
    res.send({"data": returndata});
}

async function handleContent(callData, authorized, blockNumber, res) {
    const node = web3.eth.abi.decodeParameter('bytes32', callData);
    const result = await contract.methods.contenthash(node, authorized).call({},blockNumber);
    if (result == '0x'){
       return res.send({"data": result});
    }
    
    const encodedResult = web3.eth.abi.encodeParameter('bytes', result);

    const finalSlot = await calculateContentSlot(node, authorized);

    const proof = await web3.eth.getProof(registry, [finalSlot], blockNumber);
    const hexProof = rlpEncodeProofs([proof.accountProof, proof.storageProof[0].proof]);

    const returndata = await encodeReturnData(encodedResult, finalSlot, hexProof, blockNumber);
    res.send({"data": returndata});
}

async function handleText(callData, authorized, blockNumber, res) {
    const decodedVars = web3.eth.abi.decodeParameters(['bytes32', 'string'], callData);
    const node = decodedVars[0];
    const key = decodedVars[1];

    const result = await contract.methods.text(node, key, authorized).call({},blockNumber);
    if (result == ''){
       return res.send({"data": result});
    }
    
    const encodedResult = web3.eth.abi.encodeParameter('string', result);

    const finalSlot = await calculateTextSlot(node, key, authorized);

    const proof = await web3.eth.getProof(registry, [finalSlot], blockNumber);
    const hexProof = rlpEncodeProofs([proof.accountProof, proof.storageProof[0].proof]);

    const returndata = await encodeReturnData(encodedResult, finalSlot, hexProof, blockNumber);
    res.send({"data": returndata});
}


function calculateCoinAddrSlot(node, coinType, authorized) {
    const encoded1 = web3.eth.abi.encodeParameters(['bytes32', 'uint256'], [node, 1]);
    const slot1 = web3.utils.keccak256(encoded1);
    const encoded2 = web3.eth.abi.encodeParameters(['uint256', 'bytes32'], [coinType, slot1]);
    const slot2 = web3.utils.keccak256(encoded2);
    const encoded3 = web3.eth.abi.encodeParameters(['address', 'bytes32'], [authorized, slot2]);
    return web3.utils.keccak256(encoded3);
}

function calculateTextSlot(node, key, authorized) {
    const keyHash = web3.utils.keccak256(key);
    const encoded1 = web3.eth.abi.encodeParameters(['bytes32', 'uint256'], [node, 3]);
    const slot1 = web3.utils.keccak256(encoded1);
    const encoded2 = web3.eth.abi.encodeParameters(['bytes32', 'bytes32'], [keyHash, slot1]);
    const slot2 = web3.utils.keccak256(encoded2);
    const encoded3 = web3.eth.abi.encodeParameters(['address', 'bytes32'], [authorized, slot2]);
    return web3.utils.keccak256(encoded3);
}

function calculateContentSlot(node, authorized) {
    const encoded1 = web3.eth.abi.encodeParameters(['bytes32', 'uint256'], [node, 2]);
    const slot1 = web3.utils.keccak256(encoded1);
    const encoded2 = web3.eth.abi.encodeParameters(['address', 'bytes32'], [authorized, slot1]);
    return web3.utils.keccak256(encoded2);
}

function rlpEncodeProofs(proofs){
    const decodedProofs = proofs.map(proof => {
        return proof.map(node => rlp.decode(node))
        })
    return bufferToHex(Buffer.from(rlp.encode(decodedProofs)))
}

async function encodeReturnData(encodedResult, finalSlot, hexProof, blockNumber) {
    const withdrawProof = await web3.eth.getProof(withdrawal, ['0x0000000000000000000000000000000000000000000000000000000000000000'], blockNumber);
    const withdrawalStorageRoot = withdrawProof.storageHash;
    const blockdetails = await web3.eth.getBlock(blockNumber);
    const stateRoot = blockdetails.stateRoot;
    const latestBlockhash = blockdetails.hash;
    return web3.eth.abi.encodeParameters(
        ['bytes', 'bytes32', 'bytes', 'bytes32', 'bytes32', 'bytes32'],
        [encodedResult, finalSlot, hexProof, stateRoot, withdrawalStorageRoot, latestBlockhash]
    );
}
