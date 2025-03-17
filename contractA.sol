// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ContractA {
    address public contractB;
    address public relayer;
    
    event SynSent(address indexed sender);
    event SynAckSent(address indexed sender);
    event AckReceived(address indexed from);

    modifier onlyRelayer() {
        require(msg.sender == relayer, "Only the relayer can call this function");
        _;
    }

    constructor(address _relayer) {
        relayer = _relayer;
    }

    function setContractB(address _contractB) external {
        require(contractB == address(0), "Contract B already set");
        contractB = _contractB;
    }

    function sendSyn() external {
        require(contractB != address(0), "Contract B not set");
        emit SynSent(msg.sender);
    }

    function receiveAck() external onlyRelayer {
        emit AckReceived(msg.sender);
        sendSynAck();
    }

    function sendSynAck() internal {
        emit SynAckSent(msg.sender);
    }
}