// wallet.js

// Basic wallet connection functions
async function connectWallet() {
    if (window.ethereum) {
        try {
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            const walletAddress = accounts[0];
            window.location.href = `/create-profile?wallet=${walletAddress}`;
        } catch (error) {
            alert("Wallet connection failed: " + error.message);
        }
    } else {
        alert("MetaMask not found. Please install MetaMask.");
    }
}

async function loginUser() {
    if (window.ethereum) {
        try {
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            const walletAddress = accounts[0];
            window.location.href = `/login?wallet=${walletAddress}`;
        } catch (err) {
            alert("Wallet connection failed: " + err.message);
        }
    } else {
        alert("Please install MetaMask to login.");
    }
}

async function createBankProfile() {
    if (window.ethereum) {
        try {
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            const walletAddress = accounts[0];
            window.location.href = `/create-bank-profile?wallet=${walletAddress}`;
        } catch (error) {
            alert("Wallet connection failed: " + error.message);
        }
    } else {
        alert("MetaMask not found. Please install MetaMask.");
    }
}

// New functions for bank operations
async function sendMessage(receiverWallet) {
    if (!window.ethereum) {
        alert("MetaMask not found. Please install MetaMask.");
        return;
    }

    const message = prompt("Enter your message:");
    if (!message) return;

    try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const sender = accounts[0];

        const response = await fetch('/send-message', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                receiver: receiverWallet,
                message: message,
                sender: sender
            })
        });

        const result = await response.json();
        if (result.success) {
            alert("Message sent successfully!");
            location.reload();
        } else {
            alert("Failed to send message: " + (result.error || "Unknown error"));
        }
    } catch (error) {
        alert("Error: " + error.message);
    }
}

async function acceptDeal(dealId) {
    try {
        const response = await fetch(`/accept-deal/${dealId}`);
        const result = await response.json();

        if (result.success) {
            alert('Deal accepted successfully!');
            location.reload();
        } else {
            alert('Error: ' + (result.message || 'Failed to accept deal'));
        }
    } catch (error) {
        console.error('Error accepting deal:', error);
        alert('Error accepting deal');
    }
}

async function createDeal(userWallet) {
    if (!window.ethereum) {
        alert("MetaMask not found. Please install MetaMask.");
        return;
    }

    const amount = prompt("Enter loan amount:");
    if (!amount) return;

    const startDate = prompt("Enter start date (YYYY-MM-DD):");
    if (!startDate) return;

    const deadline = prompt("Enter deadline (YYYY-MM-DD):");
    if (!deadline) return;

    try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const bankWallet = accounts[0];

        const formData = new FormData();
        formData.append('user_wallet', userWallet);
        formData.append('amount', amount);
        formData.append('start_date', startDate);
        formData.append('deadline', deadline);

        const response = await fetch('/create-deal', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        if (result.success) {
            alert("Deal created successfully!");
            location.reload();
        } else {
            alert("Failed to create deal: " + (result.error || "Unknown error"));
        }
    } catch (error) {
        alert("Error: " + error.message);
    }
}

function acceptDeal(dealId) {
    if (confirm("Are you sure you want to accept this deal?")) {
        window.location.href = `/accept-deal/${dealId}`;
    }
}

function rejectDeal(dealId) {
    if (confirm("Are you sure you want to reject this deal?")) {
        window.location.href = `/reject-deal/${dealId}`;
    }
}

async function addRating(userWallet, dealId) {
    const stars = prompt("Rate this user (1-5 stars):");
    if (!stars || isNaN(stars) || stars < 1 || stars > 5) {
        alert("Please enter a valid rating between 1 and 5");
        return;
    }

    const comment = prompt("Add a comment:");
    if (!comment) return;

    try {
        const formData = new FormData();
        formData.append('user_wallet', userWallet);
        formData.append('stars', stars);
        formData.append('comment', comment);
        formData.append('deal_id', dealId);

        const response = await fetch('/add-rating', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            alert("Rating submitted successfully!");
            location.reload();
        } else {
            alert("Failed to submit rating");
        }
    } catch (error) {
        alert("Error: " + error.message);
    }
}

function bankLogout(wallet) {
    if (confirm("Are you sure you want to logout?")) {
        window.location.href = `/banklogout?wallet=${wallet}`;
    }
}

// Search wallet functionality
function searchWallet() {
    const walletInput = document.getElementById('searchInput');
    const wallet = walletInput.value.trim();

    if (!wallet) {
        alert("Please enter a wallet address");
        return;
    }

    window.location.href = `/search?wallet=${wallet}`;
}

async function signAndSendTransaction(txData, wallet) {
    if (!window.ethereum) {
        alert("MetaMask not found. Please install MetaMask.");
        return false;
    }

    try {
        const web3 = new Web3(window.ethereum);

        // zkSync requires EIP712 type
        const tx = {
            from: wallet,  // ADD THIS LINE
            to: txData.to,
            data: txData.data,
            value: txData.value,
            gas: txData.gas,
            gasPrice: txData.gasPrice,
            nonce: txData.nonce,
            chainId: txData.chainId,
            type: '0x0'
        };
        const txHash = await window.ethereum.request({
            method: 'eth_sendTransaction',
            params: [tx]
        });

        // Wait for transaction to be mined
        const receipt = await waitForTransactionReceipt(txHash);
        return receipt.status === '0x1';
    } catch (error) {
        console.error("Transaction failed:", error);
        alert("Transaction failed: " + error.message);
        return false;
    }
}
async function waitForTransactionReceipt(txHash) {
    const web3 = new Web3(window.ethereum);
    return new Promise((resolve) => {
        const checkInterval = setInterval(async () => {
            const receipt = await web3.eth.getTransactionReceipt(txHash);
            if (receipt) {
                clearInterval(checkInterval);
                resolve(receipt);
            }
        }, 1000);
    });
}
async function signAndSendTransaction(txData) {
    try {
        const txHash = await ethereum.request({
            method: 'eth_sendTransaction',
            params: [txData]
        });
        return txHash;
    } catch (error) {
        console.error('Transaction error:', error);
        alert('Transaction failed: ' + error.message);
        return null;
    }
}
async function handleProfileCreation(txData, wallet) {
    try {
        const txHash = await signAndSendTransaction(txData, wallet);
        if (!txHash) return;

        // Verify profile creation
        const response = await fetch('/verify-profile-creation', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ txHash, wallet })
        });

        const result = await response.json();
        if (result.success) {
            alert("Profile created successfully! Redirecting to login...");
            window.location.href = `/login?wallet=${wallet}`;
        } else {
            alert("Profile creation verification failed: " + (result.error || "Unknown error"));
        }
    } catch (error) {
        alert("Error: " + error.message);
    }
}

// Initialize event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Add search functionality if search elements exist
    const searchBtn = document.getElementById('searchBtn');
    if (searchBtn) {
        searchBtn.addEventListener('click', searchWallet);
    }

    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                searchWallet();
            }
        });
    }

    // Initialize tab switching
    const tabLinks = document.querySelectorAll('.tab-link');
    tabLinks.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            document.querySelectorAll('.tab-link').forEach(t => {
                t.classList.remove('active');
            });

            // Add active class to clicked tab
            tab.classList.add('active');

            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });

            // Show the corresponding tab content
            const tabId = tab.getAttribute('data-tab');
            document.getElementById(`${tabId}Tab`).classList.add('active');
        });
    });
});

