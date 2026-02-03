# 🛡️ AXIOM Protocol

## Decentralized Content Authenticity Verification for the AI Era


![Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C?logo=ethereum)
![License](https://img.shields.io/badge/License-MIT-blue)
![Tests](https://img.shields.io/badge/Tests-31%20Passing-brightgreen)

> _In a world of deepfakes and synthetic media, AXIOM provides cryptographic proof of content authenticity._

---

## 🌟 Overview

AXIOM Protocol is a decentralized content authentication system that allows publishers to cryptographically register content hashes on-chain, enabling anyone to verify the authenticity and origin of digital content.

### The Problem

- 🤖 AI-generated content is indistinguishable from real content
- 🎭 Deepfakes and misinformation spread faster than truth
- ❓ No reliable way to prove "I published this first"

### The Solution

- ✅ Immutable on-chain proof of content registration
- ⏰ Tamper-proof timestamps tied to publisher identity
- 🔍 Instant verification for consumers and platforms

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AXIOM Protocol                        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   ┌──────────────┐    ┌──────────────────────────────┐  │
│   │  ERC1967     │    │        AxiomRouter           │  │
│   │  Proxy       │───▶│  (UUPS Upgradeable)          │  │
│   └──────────────┘    │                              │  │
│                       │  ├─ Registry   (register)    │  │
│                       │  ├─ Identity   (DID)         │  │
│                       │  ├─ Treasury   (fees)        │  │
│                       │  └─ Access     (RBAC)        │  │
│                       └──────────────────────────────┘  │
│                                  │                       │
│                       ┌──────────▼──────────┐           │
│                       │   Diamond Storage    │           │
│                       │   (AxiomStorage)     │           │
│                       └─────────────────────┘           │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## ⚡ Features

| Feature                  | Description                                               |
| ------------------------ | --------------------------------------------------------- |
| **Content Registration** | Register SHA-256 hashes with optional metadata URI        |
| **Batch Operations**     | Register multiple hashes in a single transaction          |
| **Identity System**      | Link addresses to human-readable names with verification  |
| **Anti-Front-Running**   | Record IDs bound to `hash + sender` prevent MEV attacks   |
| **Rate Limiting**        | Spam protection with configurable action limits           |
| **Enterprise Tiers**     | Custom rates and unlimited access for verified publishers |
| **Upgradeable**          | UUPS proxy pattern for future improvements                |
| **Role-Based Access**    | Granular permissions for operators, pausers, upgraders    |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/axiomprotocol.git
cd axiomprotocol

# Install dependencies
forge install

# Build
forge build

# Run tests
forge test
```

---

## 🧪 Testing

```bash
# Run all tests
forge test

# Run with verbosity
forge test -vvv

# Run specific test
forge test --match-test test_Register

# Gas report
forge test --gas-report
```

### Test Coverage

| Category           | Tests  |
| ------------------ | ------ |
| Initialization     | 2      |
| Registration       | 6      |
| Batch Registration | 2      |
| Verification       | 3      |
| Revocation         | 3      |
| Identity           | 4      |
| Treasury           | 3      |
| Access Control     | 5      |
| Rate Limiting      | 2      |
| Fuzz Tests         | 2      |
| **Total**          | **31** |

---

## 🚀 Deployment

### Local (Anvil)

```bash
# Start local node
anvil

# Deploy
forge script script/DeployAxiom.s.sol:DeployAxiomLocal --broadcast
```

### Testnet (Base Sepolia)

```bash
# Set environment variables
export PRIVATE_KEY=your_private_key
export BASE_SEPOLIA_RPC=https://sepolia.base.org

# Deploy
forge script script/DeployAxiom.s.sol:DeployAxiom \
  --rpc-url $BASE_SEPOLIA_RPC \
  --broadcast \
  --verify
```

---

## 📖 Usage

### Register Content

```solidity
// Register a content hash
bytes32 recordId = axiom.register{value: 0.0001 ether}(
    keccak256("my content"),
    "ipfs://QmMetadataHash"
);
```

### Verify Content

```solidity
// Verify content authenticity
(bool isValid, AxiomTypes.AxiomRecord memory record) = axiom.verify(
    contentHash,
    claimedIssuer
);

if (isValid) {
    // Content is authentic and was registered by claimedIssuer
}
```

### Register Identity

```solidity
// Register a human-readable identity
axiom.registerIdentity("Reuters News", "ipfs://proofDocument");

// Resolve by name
address publisher = axiom.resolveByName("Reuters News");
```

---

## 🔐 Security

### Protections

- **Reentrancy Guard** - All state-changing functions protected
- **Access Control** - Role-based permissions with OpenZeppelin
- **Pausable** - Emergency stop mechanism
- **Anti-Front-Running** - Records bound to sender address
- **Rate Limiting** - Configurable spam protection

### Roles

| Role                 | Permissions                |
| -------------------- | -------------------------- |
| `DEFAULT_ADMIN_ROLE` | Full protocol control      |
| `OPERATOR_ROLE`      | Ban users, dispute content |
| `ENTERPRISE_ROLE`    | Bypass rate limits         |
| `PAUSER_ROLE`        | Pause/unpause protocol     |
| `UPGRADER_ROLE`      | Upgrade implementation     |

---

## 📁 Project Structure

```
axiomprotocol/
├── src/
│   ├── AxiomRouter.sol          # Main entry point (UUPS)
│   ├── core/
│   │   ├── AxiomRegistry.sol    # Registration logic
│   │   ├── AxiomIdentity.sol    # Identity management
│   │   └── AxiomTreasury.sol    # Fee handling
│   ├── access/
│   │   └── AxiomAccess.sol      # RBAC & moderation
│   ├── libraries/
│   │   └── AxiomTypes.sol       # Data structures
│   ├── storage/
│   │   └── AxiomStorage.sol     # Diamond storage
│   └── interfaces/
│       ├── IAxiomRegistry.sol
│       ├── IAxiomIdentity.sol
│       └── IAxiomTreasury.sol
├── script/
│   └── DeployAxiom.s.sol        # Deployment scripts
├── test/
│   └── AxiomRouter.t.sol        # Comprehensive tests
└── foundry.toml
```

---

## 🗺️ Roadmap

- [x] **Phase 1:** Core smart contracts
- [x] **Phase 1:** Comprehensive test suite
- [ ] **Phase 2:** Frontend (Verifier & Publisher Dashboard)
- [ ] **Phase 3:** API & SDK for integrations
- [ ] **Phase 4:** Security audit
- [ ] **Phase 5:** Mainnet deployment (Base)

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔗 Links

- [Documentation](#) _(Coming Soon)_
- [Frontend App](#) _(Coming Soon)_
- [API Reference](#) _(Coming Soon)_

---

<p align="center">
  <b>Built with ❤️ for a more trustworthy internet</b>
</p>
