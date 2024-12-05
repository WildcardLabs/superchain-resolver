// SPDX-License-Identifier: MIT
pragma solidity ^ 0.8.20;

abstract contract Context {
    function _msgSender() internal view virtual returns(address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns(bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns(uint256) {
        return 0;
    }
}

abstract contract Ownable is Context {
    address private _owner;
    error OwnableUnauthorizedAccount(address account);
    error OwnableInvalidOwner(address owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor(address initialOwner) {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
    }
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function owner() public view virtual returns(address) {
        return _owner;
    }

    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

interface INameWrapper {
    function ownerOf(uint256 id) external view returns(address);
}
interface ENS {
    function owner(bytes32 node) external view returns(address);
}
interface IERC20 {
    function transfer(address to, uint256 value) external returns(bool);
}

interface Verifier {
    function resolveWithProof(bytes calldata response, bytes calldata extraData) external view returns(bytes memory);
}

contract Resolver is Ownable {
    string public url;
    mapping(address => bool) public signers;
    event NewSigners(address[] signers);
    error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData);

    ENS immutable ens = ENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e); //ENS registry address
    INameWrapper immutable nameWrapper = INameWrapper(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401); //ENS namewrapper address (mainnet)
    constructor(address initialOwner, string memory _url, address[] memory _signers) Ownable(initialOwner) {
        url = _url;
        for (uint i = 0; i < _signers.length; i++) {
            signers[_signers[i]] = true;
        }
        emit NewSigners(_signers);
    }

    struct ensverifier {address ensverifier;}
    mapping(uint256 => ensverifier) public verifierOf;

    function addChain(uint256 chainId, address l2Verifier) external {
        require(signers[msg.sender], "Not a signer");
        verifierOf[chainId].ensverifier = l2Verifier;
    }

    function setURL(string calldata _url) external {
        require(signers[msg.sender], "Not a signer");
        url = _url;
    }

    function setSigners(address[] calldata _signers) external {
        require(signers[msg.sender], "Not a signer");
        for (uint i = 0; i < _signers.length; i++) {
            signers[_signers[i]] = true;
        }
        emit NewSigners(_signers);
    }

    function decodeData(bytes memory callData) public pure returns(bytes4 functionSelector, bytes memory callDataWithoutSelector, bytes32 node) {
        assembly {
            functionSelector:= mload(add(callData, 0x20))
        }
        callDataWithoutSelector = new bytes(callData.length - 4);
        for (uint256 i = 0; i < callData.length - 4; i++) {
            callDataWithoutSelector[i] = callData[i + 4];
        }
        if (functionSelector == 0x3b3b57de || functionSelector == 0xbc1c58d1) {
            (node) = abi.decode(callDataWithoutSelector, (bytes32));
        } else if (functionSelector == 0xf1cb7e06) {
            (node, ) = abi.decode(callDataWithoutSelector, (bytes32, uint256));
        } else if (functionSelector == 0x59d1d43c) {
            (node, ) = abi.decode(callDataWithoutSelector, (bytes32, string));
        } else {
            revert("Record type not supported");
        }
        return (functionSelector, callDataWithoutSelector, node);
    }

    function decodeNameAndComputeNamehashes(bytes memory input) public pure returns(bytes32[] memory) {
        uint pos = 0;
        uint labelsCount = 0;
        // First pass to count the number of labels
        while (pos < input.length) {
            uint8 length = uint8(input[pos]);
            if (length == 0) {
                break;
            }
            pos += length + 1;
            labelsCount++;
        }
        // Reset position for the second pass
        pos = 0;
        // We need an array of labelsCount - 1 for the upper-level domains
        string[] memory labels = new string[](labelsCount);
        // Extract all labels
        for (uint labelIndex = 0; pos < input.length; labelIndex++) {
            uint8 length = uint8(input[pos]);
            if (length == 0) {
                break;
            }
            require(length > 0 && length <= 63, "Invalid length");
            bytes memory labelBytes = new bytes(length);
            for (uint i = 0; i < length; i++) {
                labelBytes[i] = input[pos + i + 1];
            }
            labels[labelIndex] = string(labelBytes);
            pos += length + 1;
        }
        // Compute the number of upper-level domains excluding the TLD and the first label
        uint upperDomainCount = labelsCount > 1 ? labelsCount - 2 : 0;
        bytes32[] memory namehashes = new bytes32[](upperDomainCount);
        // Compute namehashes for each upper-level domain, skipping the first label and the TLD
        for (uint i = 1; i < labelsCount - 1; i++) {
            string memory domain = labels[i];
            for (uint j = i + 1; j < labelsCount; j++) {
                domain = string(abi.encodePacked(labels[j], ".", domain));
            }
            namehashes[i - 1] = namehash(domain);
        }
        return namehashes;
    }

    function namehash(string memory name) public pure returns(bytes32) {
        bytes32 node = 0x0000000000000000000000000000000000000000000000000000000000000000;
        if (bytes(name).length > 0) {
            string[] memory labels = splitLabels(name);
            for (uint i = labels.length; i > 0; i--) {
                node = keccak256(abi.encodePacked(node, keccak256(abi.encodePacked(labels[i - 1]))));
            }
        }
        return node;
    }

    function splitLabels(string memory name) public pure returns(string[] memory) {
        uint labelCount = 1;
        for (uint i = 0; i < bytes(name).length; i++) {
            if (bytes(name)[i] == '.') {
                labelCount++;
            }
        }
        string[] memory labels = new string[](labelCount);
        uint labelIndex = 0;
        uint start = 0;
        for (uint i = 0; i <= bytes(name).length; i++) {
            if (i == bytes(name).length || bytes(name)[i] == '.') {
                bytes memory labelBytes = new bytes(i - start);
                for (uint j = 0; j < labelBytes.length; j++) {
                    labelBytes[j] = bytes(name)[start + j];
                }
                labels[labelIndex++] = string(labelBytes);
                start = i + 1;
            }
        }
        return labels;
    }

    function findAuthorizedAddress(bytes memory input) public view returns(address, bytes32) {
        bytes32[] memory namehashes = decodeNameAndComputeNamehashes(input);
        for (uint i = 0; i < namehashes.length; i++) {
            address authorized = ens.owner(namehashes[i]);
            if (authorized != address(0)) {
                return (authorized, namehashes[i]);
            }
        }
        return (address(0), 0x0000000000000000000000000000000000000000000000000000000000000000);
    }

    function resolve(bytes calldata name, bytes calldata data) external view returns(bytes memory) {
        (bytes4 functionSelector, bytes memory callDataWithoutSelector, bytes32 node) = decodeData(data);
        address authorized = ens.owner(node);
        if (authorized == address(0)) {
            (authorized, node) = findAuthorizedAddress(name);
        }
        if (authorized == address(nameWrapper)) {
            authorized = nameWrapper.ownerOf(uint256(node));
        }
        bytes memory callData = abi.encode(functionSelector, callDataWithoutSelector, authorized);
        string[] memory urls = new string[](1);
        urls[0] = url;
        revert OffchainLookup(address(this), urls, callData, Resolver.resolveWithProof.selector, callData);
    }

    function resolve(bytes calldata name, bytes calldata data, address context) external view returns(bytes memory) {
        (bytes4 functionSelector, bytes memory callDataWithoutSelector,) = decodeData(data);
        address authorized = context;
        bytes memory callData = abi.encode(functionSelector, callDataWithoutSelector, authorized);
        string[] memory urls = new string[](1);
        urls[0] = url;
        revert OffchainLookup(address(this), urls, callData, Resolver.resolveWithProof.selector, callData);
    }

    function resolveWithProof(bytes calldata response, bytes calldata extraData) external view returns(bytes memory result) {
        uint256 chainId;
        (chainId, , , , , , ) = abi.decode(response, (uint256, bytes, bytes32, bytes, bytes32, bytes32, bytes32));
        address l2Verifier = verifierOf[chainId].ensverifier;
        result = Verifier(l2Verifier).resolveWithProof(response, extraData);
        return result;
    }

    function supportsInterface(bytes4 interfaceID) public pure returns(bool) {
        return interfaceID == 0x9061b923;
    }

    function withdrawERC20(address tokenAddr, uint256 amount) external onlyOwner {
        IERC20(tokenAddr).transfer(owner(), amount);
    }

    function withdraw(address payable _to) external onlyOwner {
        _to.transfer(address(this).balance);
    }
}
