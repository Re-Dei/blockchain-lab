// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract EnglishAuction {
    address payable public seller;
    uint public endAt;
    bool public started;
    bool public ended;
    
    address public highestBidder;
    uint public highestBid;
    uint public minBidIncrement;
    
    mapping(address => uint) public pendingReturns;
    
    event Start(uint startTime, uint endTime);
    event Bid(address indexed bidder, uint amount);
    event End(address winner, uint amount);
    event ItemClaimed(address winner);
    
    constructor(uint _minBidIncrement) {
        seller = payable(msg.sender);
        minBidIncrement = _minBidIncrement;
    }
    
    // Modifiers
    modifier onlySeller() {
        require(msg.sender == seller, "Only seller can call this function");
        _;
    }
    
    modifier notStarted() {
        require(!started, "Auction already started");
        _;
    }
    
    modifier hasStarted() {
        require(started, "Auction not started yet");
        _;
    }
    
    modifier notEnded() {
        require(!ended, "Auction already ended");
        _;
    }
    
    modifier hasEnded() {
        require(ended, "Auction not ended yet");
        _;
    }
    
    function start(uint _durationInSeconds) external onlySeller notStarted {
        started = true;
        endAt = block.timestamp + _durationInSeconds;
        
        emit Start(block.timestamp, endAt);
    }
    
    function bid() external payable hasStarted notEnded {
        require(block.timestamp < endAt, "Auction already ended");
        
        uint minValidBid;
        if (highestBid > 0) {
            minValidBid = highestBid + ((highestBid * minBidIncrement) / 100);
            require(msg.value >= minValidBid, "Bid not high enough");
        } else {
            require(msg.value > 0, "Bid must be greater than 0");
        }
        
        if (highestBidder != address(0)) {
            pendingReturns[highestBidder] += highestBid;
        }
        
        highestBidder = msg.sender;
        highestBid = msg.value;
        
        emit Bid(msg.sender, msg.value);
    }
    
    function withdraw() external {
        uint amount = pendingReturns[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        
        pendingReturns[msg.sender] = 0;
        
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    function end() external onlySeller hasStarted notEnded {
        require(block.timestamp >= endAt, "Auction cannot be ended before endAt time");
        
        ended = true;
        
        if (highestBidder != address(0)) {
            (bool success, ) = seller.call{value: highestBid}("");
            require(success, "Transfer to seller failed");
        }
        
        emit End(highestBidder, highestBid);
    }
    
    function claimItem() external hasEnded {
        require(msg.sender == highestBidder, "Only highest bidder can claim");
        
        
        emit ItemClaimed(highestBidder);
    }
    
    function timeRemaining() external view hasStarted notEnded returns (uint) {
        if (block.timestamp >= endAt) return 0;
        return endAt - block.timestamp;
    }
    
    function getMinimumBid() external view returns (uint) {
        if (highestBid == 0) return 1; // Minimum 1 wei for first bid
        return highestBid + ((highestBid * minBidIncrement) / 100);
    }
}