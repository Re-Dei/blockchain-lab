// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Escrow {
    address public buyer;
    address public seller;
    address public arbiter;
    uint public amount;
    bool public fundsDeposited;
    bool public isComplete;

    enum State { AwaitingPayment, AwaitingDelivery, InDispute, Complete }
    State public currentState;

    modifier onlyBuyer() {
        require(msg.sender == buyer, "Only buyer allowed");
        _;
    }

    modifier onlySeller() {
        require(msg.sender == seller, "Only seller allowed");
        _;
    }

    modifier onlyArbiter() {
        require(msg.sender == arbiter, "Only arbiter allowed");
        _;
    }

    modifier inState(State expected) {
        require(currentState == expected, "Invalid state");
        _;
    }

    constructor(address _seller, address _arbiter) {
        buyer = msg.sender;
        seller = _seller;
        arbiter = _arbiter;
        currentState = State.AwaitingPayment;
    }

    function deposit() public payable onlyBuyer inState(State.AwaitingPayment) {
        require(msg.value > 0, "Must send ETH");
        amount = msg.value;
        fundsDeposited = true;
        currentState = State.AwaitingDelivery;
    }

    function approveDelivery() public onlyBuyer inState(State.AwaitingDelivery) {
        _transferToSeller();
    }

    function raiseDispute() public onlyBuyer inState(State.AwaitingDelivery) {
        currentState = State.InDispute;
    }

    function resolveDispute(bool releaseToSeller) public onlyArbiter inState(State.InDispute) {
        if (releaseToSeller) {
            _transferToSeller();
        } else {
            _refundToBuyer();
        }
    }

    function _transferToSeller() internal {
        require(!isComplete, "Already resolved");
        isComplete = true;
        currentState = State.Complete;
        payable(seller).transfer(amount);
    }

    function _refundToBuyer() internal {
        require(!isComplete, "Already resolved");
        isComplete = true;
        currentState = State.Complete;
        payable(buyer).transfer(amount);
    }

    function getContractBalance() public view returns (uint) {
        return address(this).balance;
    }
}
