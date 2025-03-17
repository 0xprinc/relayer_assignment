// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ContractB {
    address public contractA;
    address public relayer;

    event AckSent(address indexed sender);
    event SynReceived(address indexed from);
    event SynAckReceived(address indexed from);

    modifier onlyRelayer() {
        require(msg.sender == relayer, "Only the relayer can call this function");
        _;
    }

    constructor(address _relayer) {
        relayer = _relayer;
    }

    function setContractA(address _contractA) external {
        require(contractA == address(0), "Contract A already set");
        contractA = _contractA;
    }

    function receiveSyn() external onlyRelayer {
        emit SynReceived(msg.sender);
        sendAck();
    }

    function sendAck() internal {
        emit AckSent(msg.sender);
    }

    function receiveSynAck() external onlyRelayer {
        emit SynAckReceived(msg.sender);
    }
}