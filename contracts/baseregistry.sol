
//SPDX-License-Identifier: MIT
pragma solidity ^ 0.8.24;

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
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

    function owner() public view virtual returns (address) {
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

interface IERC20 {
 function transfer(address to, uint256 value) external returns (bool); 
}  

contract BaseRecords is Ownable { 

constructor(address initialOwner) Ownable(initialOwner) {}

struct coinHash {bytes32 hash;}
    mapping(bytes32 => mapping(uint256 => mapping(address => coinHash))) public coinHashOf;

struct contentHash {bytes32 hash;}
    mapping(bytes32 => mapping(address => contentHash)) public contentHashOf;

struct textHash {bytes32 hash;}
    mapping(bytes32 => mapping(bytes32 => mapping(address => textHash))) public textHashOf;

struct coinAddr {bytes addr;}
    mapping(bytes32 => mapping(uint256 => mapping(address => coinAddr))) public coinAddrOf;

struct content {bytes content;}
    mapping(bytes32 => mapping(address => content)) public contentOf;

struct _text {bytes text;}
    mapping(bytes32 => mapping(string => mapping(address => _text))) public textOf;


event addrChanged(
        bytes32 indexed node,
        uint256 coinType,
        bytes newAddress,
        address setBy
    );

event addrChanged(
        bytes32 indexed node,
        address newAddress,
        address setBy
    );

function setAddr(
        bytes32 node,
        address a
    ) public {
        setAddr(node, 60, abi.encodePacked(a));
    }

function setAddr(
        bytes32 node,
        uint256 coinType,
        bytes memory a
    ) public {
        coinAddrOf[node][coinType][msg.sender].addr = abi.encode(a, block.timestamp);
        coinHashOf[node][coinType][msg.sender].hash = keccak256(abi.encodePacked(a));
        emit addrChanged(node, coinType, a, msg.sender);
    }

event contenthashChanged(
        bytes32 indexed node,
        bytes hash,
        address setBy
    );

function setContenthash(
        bytes32 node,
        bytes memory _contenthash
    ) external {
        contentOf[node][msg.sender].content = abi.encode(_contenthash, block.timestamp);
        contentHashOf[node][msg.sender].hash = keccak256(abi.encodePacked(_contenthash));
        emit contenthashChanged(node, _contenthash, msg.sender);
    }

event textChanged(
        bytes32 indexed node,
        string key,
        string value,
        address setBy
    );

function setText(
        bytes32 node,
        string calldata key,
        string calldata value
    ) external {
        textOf[node][key][msg.sender].text = abi.encode(value, block.timestamp);
        textHashOf[node][keccak256(abi.encodePacked(key))][msg.sender].hash = keccak256(abi.encodePacked(value));
        emit textChanged(node, key, value, msg.sender);
    }

function addr(
        bytes32 node,
        address owner
    ) public view returns(address) {
        (bytes memory addrEth,) = abi.decode(coinAddrOf[node][60][owner].addr, (bytes, uint256));
        return address(bytes20(addrEth));
    }

function addrAndTimestamp(
        bytes32 node,
        address owner
    ) public view returns(bytes memory) {
        return coinAddrOf[node][60][owner].addr;
    }

function addr(
        bytes32 node,
        uint256 coinType,
        address owner
    ) public view returns(bytes memory) {
        (bytes memory addrEth,) = abi.decode(coinAddrOf[node][coinType][owner].addr, (bytes, uint256));
        return addrEth;
    }

function addrAndTimestamp(
        bytes32 node,
        uint256 coinType,
        address owner
    ) public view returns(bytes memory) {
        return coinAddrOf[node][coinType][owner].addr;
    }

function contenthash(
        bytes32 node,
        address owner
    ) public view returns(bytes memory) {
        (bytes memory content_,) = abi.decode(contentOf[node][owner].content, (bytes, uint256));
        return content_;
    }

function contenthashAndTimestamp(
        bytes32 node,
        address owner
    ) public view returns(bytes memory) {
        return contentOf[node][owner].content;
    }

function text(
        bytes32 node,
        string memory key,
        address owner
    ) public view returns(string memory) {
        (string memory text_,) = abi.decode(textOf[node][key][owner].text, (string, uint256));
        return text_;
    }

function textAndTimestamp(
        bytes32 node,
        string memory key,
        address owner
    ) public view returns(bytes memory) {
        return textOf[node][key][owner].text;
    }

function multicall(bytes[] calldata data) external returns(bytes[] memory results) {
        results = new bytes[](data.length);
        for(uint i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);
            require(success);
            results[i] = result;
        }
        return results;
    }

function withdrawERC20(address tokenAddr, uint256 amount) external {
        IERC20(tokenAddr).transfer(owner(), amount);
    }

function withdraw(address payable _to) external onlyOwner {
        _to.transfer(address(this).balance);
    }

}
