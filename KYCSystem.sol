// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract KYCSystem {
    address public admin;

    enum ProfileType {
        None,
        User,
        Bank,
        Admin
    }
    enum VerificationStatus {
        Unverified,
        Pending,
        Verified
    }

    struct UserProfile {
        string fullName;
        string email;
        string phone;
        string currentAddress;
        string permanentAddress;
        string currentJob;
        string nidNumber;
        string profilePicCID;
        string propertyDocsCID;
        VerificationStatus verificationStatus;
        address verifiedBy;
        bool exists;
    }

    struct BankProfile {
        string name;
        string email;
        string phone;
        string licenseNumber;
        string logoCID;
        bool approved;
        bool exists;
    }
    struct LoanRequest {
        address user;
        uint256 amount;
        uint256 duration;
        bool monthlyPayment;
        bool active;
    }

    struct LoanDeal {
        address user;
        address bank;
        uint256 amount;
        uint256 startDate;
        uint256 deadline;
        bool monthlyPayment;
        bool accepted;
        bool completed;
    }

    mapping(address => UserProfile) public userProfiles;
    mapping(address => BankProfile) public bankProfiles;
    mapping(address => ProfileType) public profileTypes;
    mapping(address => address) public verificationRequests; // User => Bank/Admin
    mapping(address => LoanRequest) public loanRequests;
    mapping(uint256 => LoanDeal) public loanDeals;
    uint256 public dealCounter = 1;

    event LoanRequestCreated(
        address indexed user,
        uint256 amount,
        uint256 duration,
        bool monthlyPayment
    );
    event DealCreated(
        uint256 indexed dealId,
        address indexed user,
        address indexed bank,
        uint256 amount,
        uint256 deadline,
        bool monthlyPayment
    );
    event DealAccepted(uint256 indexed dealId);
    event DealCompleted(uint256 indexed dealId);

    event UserProfileCreated(address indexed userAddress);
    event BankProfileCreated(address indexed bankAddress);
    event BankApproved(address indexed bankAddress);
    event VerificationRequested(address indexed user, address indexed verifier);
    event UserVerified(address indexed user, address indexed verifier);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    modifier onlyBank() {
        require(
            profileTypes[msg.sender] == ProfileType.Bank,
            "Only bank can perform this action"
        );
        _;
    }

    constructor() {
        admin = msg.sender;
        profileTypes[admin] = ProfileType.Admin;
    }

    function createUserProfile(
        string memory fullName,
        string memory email,
        string memory phone,
        string memory currentAddress,
        string memory permanentAddress,
        string memory currentJob,
        string memory nidNumber,
        string memory profilePicCID,
        string memory propertyDocsCID
    ) external {
        require(
            profileTypes[msg.sender] == ProfileType.None,
            "Profile already exists"
        );

        userProfiles[msg.sender] = UserProfile({
            fullName: fullName,
            email: email,
            phone: phone,
            currentAddress: currentAddress,
            permanentAddress: permanentAddress,
            currentJob: currentJob,
            nidNumber: nidNumber,
            profilePicCID: profilePicCID,
            propertyDocsCID: propertyDocsCID,
            verificationStatus: VerificationStatus.Unverified,
            verifiedBy: address(0),
            exists: true
        });

        profileTypes[msg.sender] = ProfileType.User;
        emit UserProfileCreated(msg.sender);
    }

    function createBankProfile(
        string memory name,
        string memory email,
        string memory phone,
        string memory licenseNumber,
        string memory logoCID
    ) external {
        require(
            profileTypes[msg.sender] == ProfileType.None,
            "Profile already exists"
        );

        bankProfiles[msg.sender] = BankProfile({
            name: name,
            email: email,
            phone: phone,
            licenseNumber: licenseNumber,
            logoCID: logoCID,
            approved: false,
            exists: true
        });

        profileTypes[msg.sender] = ProfileType.Bank;
        emit BankProfileCreated(msg.sender);
    }

    function approveBank(address bankAddress) external onlyAdmin {
        require(
            bankProfiles[bankAddress].exists,
            "Bank profile does not exist"
        );
        require(!bankProfiles[bankAddress].approved, "Bank already approved");

        bankProfiles[bankAddress].approved = true;
        emit BankApproved(bankAddress);
    }

    function requestVerification(address verifier) external {
        require(
            profileTypes[msg.sender] == ProfileType.User,
            "Only users can request verification"
        );
        require(
            profileTypes[verifier] == ProfileType.Admin ||
                (profileTypes[verifier] == ProfileType.Bank &&
                    bankProfiles[verifier].approved),
            "Invalid verifier"
        );

        verificationRequests[msg.sender] = verifier;
        userProfiles[msg.sender].verificationStatus = VerificationStatus
            .Pending;
        emit VerificationRequested(msg.sender, verifier);
    }

    function verifyUser(address userAddress) external {
        require(
            verificationRequests[userAddress] == msg.sender,
            "Not authorized to verify this user"
        );
        require(
            profileTypes[msg.sender] == ProfileType.Admin ||
                (profileTypes[msg.sender] == ProfileType.Bank &&
                    bankProfiles[msg.sender].approved),
            "Only admin or approved banks can verify"
        );

        userProfiles[userAddress].verificationStatus = VerificationStatus
            .Verified;
        userProfiles[userAddress].verifiedBy = msg.sender;
        emit UserVerified(userAddress, msg.sender);
    }

    function getProfileType(
        address wallet
    ) external view returns (ProfileType) {
        return profileTypes[wallet];
    }

    function getUserProfile(
        address user
    )
        external
        view
        returns (
            string memory,
            string memory,
            string memory,
            string memory,
            string memory,
            string memory,
            string memory,
            string memory,
            string memory,
            VerificationStatus,
            address
        )
    {
        UserProfile memory profile = userProfiles[user];
        require(profile.exists, "User profile does not exist");
        return (
            profile.fullName,
            profile.email,
            profile.phone,
            profile.currentAddress,
            profile.permanentAddress,
            profile.currentJob,
            profile.nidNumber,
            profile.profilePicCID,
            profile.propertyDocsCID,
            profile.verificationStatus,
            profile.verifiedBy
        );
    }

    function getBankProfile(
        address bank
    )
        external
        view
        returns (
            string memory,
            string memory,
            string memory,
            string memory,
            string memory,
            bool
        )
    {
        BankProfile memory profile = bankProfiles[bank];
        require(profile.exists, "Bank profile does not exist");
        return (
            profile.name,
            profile.email,
            profile.phone,
            profile.licenseNumber,
            profile.logoCID,
            profile.approved
        );
    }

    function createLoanRequest(
        uint256 amount,
        uint256 duration,
        bool monthlyPayment
    ) external {
        require(
            profileTypes[msg.sender] == ProfileType.User,
            "Only users can request loans"
        );
        loanRequests[msg.sender] = LoanRequest({
            user: msg.sender,
            amount: amount,
            duration: duration,
            monthlyPayment: monthlyPayment,
            active: true
        });
        emit LoanRequestCreated(msg.sender, amount, duration, monthlyPayment);
    }

    function createDeal(
        address user,
        uint256 amount,
        uint256 deadline,
        bool monthlyPayment
    ) external onlyBank {
        require(loanRequests[user].active, "No active loan request");
        require(loanRequests[user].amount == amount, "Amount mismatch");

        uint256 dealId = dealCounter++;
        loanDeals[dealId] = LoanDeal({
            user: user,
            bank: msg.sender,
            amount: amount,
            startDate: block.timestamp,
            deadline: deadline,
            monthlyPayment: monthlyPayment,
            accepted: false,
            completed: false
        });

        loanRequests[user].active = false;
        emit DealCreated(
            dealId,
            user,
            msg.sender,
            amount,
            deadline,
            monthlyPayment
        );
    }

    function acceptDeal(uint256 dealId) external {
        require(loanDeals[dealId].user == msg.sender, "Not authorized");
        loanDeals[dealId].accepted = true;
        emit DealAccepted(dealId);
    }

    function completeDeal(uint256 dealId) external onlyBank {
        require(loanDeals[dealId].bank == msg.sender, "Not authorized");
        loanDeals[dealId].completed = true;
        emit DealCompleted(dealId);
    }
}
