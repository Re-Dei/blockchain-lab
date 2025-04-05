// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Voting {
    struct Candidate {
        string name;
        uint voteCount;
    }

    address public owner;
    uint public votingDeadline;
    Candidate[] public candidates;

    mapping(address => bool) public isWhitelisted;
    mapping(address => bool) public hasVoted;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not contract owner");
        _;
    }

    modifier onlyWhitelisted() {
        require(isWhitelisted[msg.sender], "Not whitelisted");
        _;
    }

    modifier onlyBeforeDeadline() {
        require(block.timestamp < votingDeadline, "Voting has ended");
        _;
    }

    modifier onlyAfterDeadline() {
        require(block.timestamp >= votingDeadline, "Voting is still active");
        _;
    }

    constructor(uint _durationInMinutes) {
        owner = msg.sender;
        votingDeadline = block.timestamp + (_durationInMinutes * 1 minutes);
    }

    function addCandidate(string memory _name) public onlyOwner onlyBeforeDeadline {
        candidates.push(Candidate(_name, 0));
    }

    function whitelistVoter(address _voter) public onlyOwner {
        isWhitelisted[_voter] = true;
    }

    function vote(uint _candidateIndex) public onlyWhitelisted onlyBeforeDeadline {
        require(!hasVoted[msg.sender], "Already voted");
        require(_candidateIndex < candidates.length, "Invalid candidate");

        hasVoted[msg.sender] = true;
        candidates[_candidateIndex].voteCount++;
    }

    function getCandidates() public view returns (Candidate[] memory) {
        return candidates;
    }

    function getWinner() public view onlyAfterDeadline returns (string memory winnerName, uint winnerVotes) {
        require(candidates.length > 0, "No candidates");

        uint winningVoteCount = 0;
        uint winnerIndex = 0;

        for (uint i = 0; i < candidates.length; i++) {
            if (candidates[i].voteCount > winningVoteCount) {
                winningVoteCount = candidates[i].voteCount;
                winnerIndex = i;
            }
        }

        winnerName = candidates[winnerIndex].name;
        winnerVotes = candidates[winnerIndex].voteCount;
    }
}
