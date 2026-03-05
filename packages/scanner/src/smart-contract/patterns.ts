// =============================================================================
// @vulnhunter/scanner - Smart Contract Vulnerability Patterns Database
// =============================================================================
// A comprehensive database of known Solidity vulnerability patterns used by the
// SolidityAnalyzer to detect security issues via static analysis. Each pattern
// includes a regex, severity, CWE mapping, and remediation advice.
// =============================================================================

import { Severity } from "@vulnhunter/core";

// ---------------------------------------------------------------------------
// Pattern Interface
// ---------------------------------------------------------------------------

/**
 * Defines a single vulnerability pattern that the Solidity analyzer can match
 * against smart contract source code.
 */
export interface SolidityVulnerabilityPattern {
  /** Unique identifier for this pattern. */
  id: string;
  /** Human-readable name of the vulnerability class. */
  name: string;
  /** Detailed description of the vulnerability. */
  description: string;
  /** Regex pattern to match against Solidity source code. */
  pattern: RegExp;
  /** Severity rating if this pattern matches. */
  severity: Severity;
  /** CVSS v3.1 base score. */
  cvssScore: number;
  /** CWE identifier. */
  cweId: string;
  /** Remediation guidance. */
  remediation: string;
  /** Additional context or reference URLs. */
  references: string[];
  /** Category tag for grouping. */
  category: SolidityVulnerabilityCategory;
  /** Confidence that a match represents a true positive (0-100). */
  confidence: number;
  /**
   * Optional validator function for reducing false positives.
   * Receives the full source and the match, returns true if the finding is valid.
   */
  validate?: (source: string, match: RegExpMatchArray) => boolean;
}

/**
 * Categories for smart contract vulnerabilities.
 */
export enum SolidityVulnerabilityCategory {
  Reentrancy = "reentrancy",
  IntegerOverflow = "integer_overflow",
  AccessControl = "access_control",
  UncheckedCall = "unchecked_call",
  TxOrigin = "tx_origin",
  DelegateCall = "delegate_call",
  SelfDestruct = "self_destruct",
  TimestampDependence = "timestamp_dependence",
  FrontRunning = "front_running",
  DenialOfService = "denial_of_service",
  GasLimit = "gas_limit",
  Randomness = "randomness",
  SignatureReplay = "signature_replay",
  FlashLoan = "flash_loan",
  OracleManipulation = "oracle_manipulation",
  StorageCollision = "storage_collision",
  Visibility = "visibility",
  DeprecatedFeature = "deprecated_feature",
  InformationLeak = "information_leak",
  LogicError = "logic_error",
}

// ---------------------------------------------------------------------------
// Reentrancy Patterns
// ---------------------------------------------------------------------------

const reentrancyPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-REENTRANCY-001",
    name: "Reentrancy via External Call Before State Update",
    description:
      "A state variable is updated after an external call (.call, .send, .transfer, or contract call). An attacker can re-enter the function before the state is updated, draining funds or corrupting state. This is the classic reentrancy vulnerability exploited in the DAO hack.",
    pattern:
      /\.call\s*\{[^}]*value\s*:/m,
    severity: Severity.Critical,
    cvssScore: 9.8,
    cweId: "CWE-841",
    remediation:
      "Follow the Checks-Effects-Interactions pattern: update all state variables before making external calls. Use OpenZeppelin's ReentrancyGuard (nonReentrant modifier). Consider using .transfer() or .send() for simple ETH transfers (limited to 2300 gas, though this has been deprecated as a reliable protection post-EIP-1884).",
    references: [
      "https://swcregistry.io/docs/SWC-107",
      "https://docs.soliditylang.org/en/latest/security-considerations.html#re-entrancy",
    ],
    category: SolidityVulnerabilityCategory.Reentrancy,
    confidence: 70,
    validate: (source, match) => {
      // Check if there's a state update after the call
      const matchIndex = match.index ?? 0;
      const afterCall = source.slice(matchIndex + (match[0]?.length ?? 0), matchIndex + 500);
      // Look for assignment operations after the call
      return /\b\w+\s*[\-+*]?=\s*/.test(afterCall);
    },
  },
  {
    id: "SOL-REENTRANCY-002",
    name: "Cross-Function Reentrancy Risk",
    description:
      "An external call is made within a public/external function that shares state with other public functions. An attacker can exploit reentrancy across multiple functions that depend on the same state.",
    pattern:
      /function\s+\w+\s*\([^)]*\)\s*(?:public|external)[^{]*\{[^}]*\.call\b/m,
    severity: Severity.High,
    cvssScore: 8.1,
    cweId: "CWE-841",
    remediation:
      "Apply the ReentrancyGuard to all functions that share state and make external calls. Use the Checks-Effects-Interactions pattern consistently. Consider using a pull-payment pattern instead of push-payment.",
    references: [
      "https://swcregistry.io/docs/SWC-107",
      "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
    ],
    category: SolidityVulnerabilityCategory.Reentrancy,
    confidence: 55,
  },
  {
    id: "SOL-REENTRANCY-003",
    name: "Read-Only Reentrancy via View Function",
    description:
      "A view function reads state that may be inconsistent during an external call in another function. An attacker can re-enter through the view function to read stale state (e.g., incorrect token balances or exchange rates).",
    pattern:
      /function\s+\w+\s*\([^)]*\)\s*(?:public|external)\s+view[^{]*\{[^}]*(?:balanceOf|totalSupply|getReserves|slot0)/m,
    severity: Severity.High,
    cvssScore: 7.5,
    cweId: "CWE-841",
    remediation:
      "Protect against read-only reentrancy by using a reentrancy lock that also blocks view functions. Ensure external protocols that read your state do so safely. Consider using transient storage (EIP-1153) for reentrancy guards in Solidity >=0.8.24.",
    references: [
      "https://www.chainsecurity.com/blog/read-only-reentrancy",
    ],
    category: SolidityVulnerabilityCategory.Reentrancy,
    confidence: 45,
  },
];

// ---------------------------------------------------------------------------
// Integer Overflow / Underflow Patterns
// ---------------------------------------------------------------------------

const integerPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-INT-001",
    name: "Unchecked Arithmetic in Solidity <0.8.0",
    description:
      "Arithmetic operations without SafeMath or unchecked blocks in Solidity versions prior to 0.8.0 can silently overflow or underflow, leading to incorrect balances, unauthorized minting, or access control bypass.",
    pattern:
      /pragma\s+solidity\s+(?:\^?0\.[4-7]\.\d+|>=?\s*0\.[4-7]\.\d+)/m,
    severity: Severity.High,
    cvssScore: 8.1,
    cweId: "CWE-190",
    remediation:
      "Upgrade to Solidity >=0.8.0 which has built-in overflow/underflow checks. If upgrading is not possible, use OpenZeppelin's SafeMath library for all arithmetic operations.",
    references: [
      "https://swcregistry.io/docs/SWC-101",
      "https://docs.soliditylang.org/en/v0.8.0/080-breaking-changes.html",
    ],
    category: SolidityVulnerabilityCategory.IntegerOverflow,
    confidence: 85,
  },
  {
    id: "SOL-INT-002",
    name: "Unchecked Block Disables Overflow Protection",
    description:
      "An unchecked { } block is used around arithmetic operations in Solidity >=0.8.0. While this saves gas, it disables built-in overflow/underflow checks, reintroducing the classic vulnerability.",
    pattern:
      /unchecked\s*\{[^}]*(?:\+\+|\-\-|\+\=|\-\=|\*\=|[\+\-\*\/]\s*\w)/m,
    severity: Severity.Medium,
    cvssScore: 6.5,
    cweId: "CWE-190",
    remediation:
      "Only use unchecked blocks for operations that are mathematically proven to never overflow (e.g., loop counters bounded by array length). Add explicit bounds checks inside unchecked blocks for any user-influenced values.",
    references: [
      "https://swcregistry.io/docs/SWC-101",
      "https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic",
    ],
    category: SolidityVulnerabilityCategory.IntegerOverflow,
    confidence: 60,
  },
];

// ---------------------------------------------------------------------------
// Access Control Patterns
// ---------------------------------------------------------------------------

const accessControlPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-AC-001",
    name: "Missing Access Control on Critical Function",
    description:
      "A function that modifies important state (owner, admin, paused, balance) or performs privileged operations (mint, burn, withdraw, selfdestruct) lacks access control modifiers. Anyone can call this function.",
    pattern:
      /function\s+(?:set(?:Owner|Admin)|withdraw(?:All|Funds)?|mint|burn|pause|unpause|upgrade|destroy|kill)\s*\([^)]*\)\s*(?:public|external)(?!\s+view)(?!\s+pure)(?![^{]*(?:onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender))/m,
    severity: Severity.Critical,
    cvssScore: 9.8,
    cweId: "CWE-284",
    remediation:
      "Add proper access control modifiers to all state-changing functions. Use OpenZeppelin's Ownable or AccessControl contracts. Apply the principle of least privilege: use role-based access control for different administrative functions.",
    references: [
      "https://swcregistry.io/docs/SWC-105",
      "https://docs.openzeppelin.com/contracts/5.x/access-control",
    ],
    category: SolidityVulnerabilityCategory.AccessControl,
    confidence: 75,
  },
  {
    id: "SOL-AC-002",
    name: "Unprotected Initialize Function",
    description:
      "An initializer function (initialize, init, setup) in a proxy/upgradeable contract lacks access control or the initializer modifier. An attacker can front-run the initialization and take ownership of the proxy.",
    pattern:
      /function\s+(?:initialize|init|setup)\s*\([^)]*\)\s*(?:public|external)(?![^{]*(?:initializer|onlyOwner|require\s*\(\s*msg\.sender))/m,
    severity: Severity.Critical,
    cvssScore: 9.8,
    cweId: "CWE-284",
    remediation:
      "Use OpenZeppelin's Initializable contract and the 'initializer' modifier to ensure the function can only be called once. Add access control to the initialize function. Use a constructor or deploy script to immediately initialize after deployment.",
    references: [
      "https://swcregistry.io/docs/SWC-105",
      "https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#initializers",
    ],
    category: SolidityVulnerabilityCategory.AccessControl,
    confidence: 80,
  },
];

// ---------------------------------------------------------------------------
// Unchecked External Call Patterns
// ---------------------------------------------------------------------------

const uncheckedCallPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-UNCHECKED-001",
    name: "Unchecked Return Value of Low-Level Call",
    description:
      "The return value of a low-level .call(), .delegatecall(), or .staticcall() is not checked. If the call fails silently, the contract continues execution with incorrect assumptions, potentially leading to loss of funds.",
    pattern:
      /(?:address\([^)]*\)|[\w.]+)\.(?:call|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\([^)]*\)\s*;/m,
    severity: Severity.High,
    cvssScore: 7.5,
    cweId: "CWE-252",
    remediation:
      "Always check the return value of low-level calls: (bool success, ) = target.call{value: amount}(\"\"); require(success, \"Call failed\");. Consider using OpenZeppelin's Address.sendValue() for ETH transfers.",
    references: [
      "https://swcregistry.io/docs/SWC-104",
    ],
    category: SolidityVulnerabilityCategory.UncheckedCall,
    confidence: 80,
    validate: (source, match) => {
      // Check that the return value is not captured
      const matchStr = match[0] ?? "";
      const beforeMatch = source.slice(Math.max(0, (match.index ?? 0) - 50), match.index ?? 0);
      // If we see (bool success, ) or similar before the call, it's checked
      return !(
        beforeMatch.includes("(bool") ||
        beforeMatch.includes("= ") ||
        matchStr.includes("require") ||
        matchStr.includes("assert")
      );
    },
  },
  {
    id: "SOL-UNCHECKED-002",
    name: "Unchecked send() Return Value",
    description:
      "The return value of .send() is not checked. Unlike .transfer(), .send() does not revert on failure -- it returns false. If the return value is ignored, failed ETH transfers go undetected.",
    pattern:
      /\.send\s*\([^)]*\)\s*;/m,
    severity: Severity.Medium,
    cvssScore: 5.3,
    cweId: "CWE-252",
    remediation:
      "Check the return value: require(payable(recipient).send(amount), \"Send failed\");. Or use .transfer() which auto-reverts, or .call{value: amount}(\"\") with explicit success check.",
    references: [
      "https://swcregistry.io/docs/SWC-104",
    ],
    category: SolidityVulnerabilityCategory.UncheckedCall,
    confidence: 75,
    validate: (source, match) => {
      const beforeMatch = source.slice(Math.max(0, (match.index ?? 0) - 40), match.index ?? 0);
      return !beforeMatch.includes("require") && !beforeMatch.includes("if (") && !beforeMatch.includes("if(");
    },
  },
];

// ---------------------------------------------------------------------------
// tx.origin Patterns
// ---------------------------------------------------------------------------

const txOriginPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-TXORIGIN-001",
    name: "tx.origin Used for Authentication",
    description:
      "tx.origin is used for access control or authentication. Unlike msg.sender, tx.origin is the original external account that initiated the transaction, not the immediate caller. A malicious contract can trick a user into calling it, and then call the vulnerable contract with the user's tx.origin.",
    pattern:
      /require\s*\(\s*tx\.origin\s*==|if\s*\(\s*tx\.origin\s*==|tx\.origin\s*==\s*(?:owner|admin)/m,
    severity: Severity.High,
    cvssScore: 7.5,
    cweId: "CWE-284",
    remediation:
      "Replace tx.origin with msg.sender for all authentication checks. tx.origin should never be used for authorization. If you need to ensure the caller is an EOA, use require(msg.sender == tx.origin) -- but be aware this breaks composability with smart contract wallets.",
    references: [
      "https://swcregistry.io/docs/SWC-115",
      "https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin",
    ],
    category: SolidityVulnerabilityCategory.TxOrigin,
    confidence: 90,
  },
];

// ---------------------------------------------------------------------------
// Delegatecall Patterns
// ---------------------------------------------------------------------------

const delegatecallPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-DELEGATECALL-001",
    name: "Delegatecall to User-Controlled Address",
    description:
      "A delegatecall is made to an address that may be influenced by user input. delegatecall executes the target's code in the context of the calling contract, so a malicious target can overwrite storage, steal funds, or selfdestruct the contract.",
    pattern:
      /\.delegatecall\s*\(/m,
    severity: Severity.Critical,
    cvssScore: 9.8,
    cweId: "CWE-829",
    remediation:
      "Never delegatecall to user-controlled addresses. If delegatecall is used for proxy patterns, ensure the implementation address is stored in a specific storage slot (EIP-1967) and can only be changed by authorized parties. Use OpenZeppelin's proxy contracts.",
    references: [
      "https://swcregistry.io/docs/SWC-112",
    ],
    category: SolidityVulnerabilityCategory.DelegateCall,
    confidence: 65,
  },
];

// ---------------------------------------------------------------------------
// Self-Destruct Patterns
// ---------------------------------------------------------------------------

const selfDestructPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-SELFDESTRUCT-001",
    name: "Unprotected selfdestruct",
    description:
      "A selfdestruct (or SELFDESTRUCT opcode) is present without proper access control. An attacker can destroy the contract and send its ETH balance to an arbitrary address. Note: selfdestruct behavior changed with EIP-6780 (Dencun upgrade) -- it no longer destroys the contract unless called in the same transaction as creation.",
    pattern:
      /selfdestruct\s*\(/m,
    severity: Severity.High,
    cvssScore: 8.6,
    cweId: "CWE-284",
    remediation:
      "Remove selfdestruct if not strictly necessary. If required, ensure it is protected by strict access control (onlyOwner with timelock). Note that post-Dencun (EIP-6780), selfdestruct only sends ETH but does not destroy the contract code or storage unless in the creation transaction.",
    references: [
      "https://swcregistry.io/docs/SWC-106",
      "https://eips.ethereum.org/EIPS/eip-6780",
    ],
    category: SolidityVulnerabilityCategory.SelfDestruct,
    confidence: 70,
    validate: (source, match) => {
      // Check if selfdestruct is protected by access control
      const matchIndex = match.index ?? 0;
      const contextBefore = source.slice(Math.max(0, matchIndex - 300), matchIndex);
      return !(
        contextBefore.includes("onlyOwner") ||
        contextBefore.includes("onlyAdmin") ||
        contextBefore.includes("require(msg.sender == owner") ||
        contextBefore.includes("require(msg.sender == admin")
      );
    },
  },
];

// ---------------------------------------------------------------------------
// Timestamp / Block-Related Patterns
// ---------------------------------------------------------------------------

const timestampPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-TIMESTAMP-001",
    name: "Block Timestamp Used for Critical Logic",
    description:
      "block.timestamp (or 'now' in older Solidity) is used in logic that affects ETH transfers, randomness, or access control. Miners/validators can manipulate block.timestamp by approximately 15 seconds, which can be exploited in time-sensitive operations.",
    pattern:
      /(?:block\.timestamp|now)\s*(?:[<>=!]+|[\+\-])\s*\d+/m,
    severity: Severity.Medium,
    cvssScore: 5.3,
    cweId: "CWE-829",
    remediation:
      "Do not rely on block.timestamp for critical operations. Use it only for long time intervals (hours/days) where a 15-second variation is negligible. For randomness, use Chainlink VRF. For precise timing, use block numbers or commit-reveal schemes.",
    references: [
      "https://swcregistry.io/docs/SWC-116",
    ],
    category: SolidityVulnerabilityCategory.TimestampDependence,
    confidence: 60,
  },
];

// ---------------------------------------------------------------------------
// Weak Randomness Patterns
// ---------------------------------------------------------------------------

const randomnessPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-RAND-001",
    name: "Insecure Randomness from Block Variables",
    description:
      "The contract uses block.timestamp, blockhash, block.difficulty, block.number, or block.prevrandao as a source of randomness. These values are predictable or manipulable by miners/validators, making them unsuitable for randomness in lotteries, NFT minting, or other value-bearing operations.",
    pattern:
      /keccak256\s*\([^)]*(?:block\.timestamp|blockhash|block\.difficulty|block\.number|block\.prevrandao|block\.coinbase)/m,
    severity: Severity.High,
    cvssScore: 7.5,
    cweId: "CWE-330",
    remediation:
      "Use Chainlink VRF (Verifiable Random Function) for on-chain randomness. Alternatively, implement a commit-reveal scheme. Never use block variables as the sole source of randomness for value-bearing operations.",
    references: [
      "https://swcregistry.io/docs/SWC-120",
      "https://docs.chain.link/vrf/v2/introduction",
    ],
    category: SolidityVulnerabilityCategory.Randomness,
    confidence: 85,
  },
];

// ---------------------------------------------------------------------------
// Denial of Service Patterns
// ---------------------------------------------------------------------------

const dosPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-DOS-001",
    name: "Denial of Service via Unbounded Loop",
    description:
      "A loop iterates over a dynamically-sized array that can grow without bound. If the array becomes too large, the function exceeds the block gas limit and becomes permanently uncallable, locking funds.",
    pattern:
      /for\s*\(\s*(?:uint\s+)?(?:\w+)\s*=\s*0\s*;\s*\w+\s*<\s*(?:\w+)\.length\s*;/m,
    severity: Severity.High,
    cvssScore: 7.5,
    cweId: "CWE-400",
    remediation:
      "Avoid unbounded loops over dynamic arrays. Use pagination or a pull-over-push pattern (each user withdraws their own funds). Set maximum array sizes. Consider using EnumerableSet with batch processing.",
    references: [
      "https://swcregistry.io/docs/SWC-128",
      "https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/",
    ],
    category: SolidityVulnerabilityCategory.DenialOfService,
    confidence: 65,
  },
  {
    id: "SOL-DOS-002",
    name: "DoS via External Call in Loop",
    description:
      "An external call (transfer, send, or call) is made inside a loop. If any single call fails (e.g., a malicious contract reverts), the entire transaction reverts, preventing all other recipients from receiving funds.",
    pattern:
      /for\s*\([^)]*\)\s*\{[^}]*(?:\.transfer\(|\.send\(|\.call\s*\{)/m,
    severity: Severity.High,
    cvssScore: 7.5,
    cweId: "CWE-400",
    remediation:
      "Use the pull-over-push pattern: record the amount owed to each recipient and let them withdraw individually. If batch payments are necessary, catch failures per-recipient and continue the loop.",
    references: [
      "https://swcregistry.io/docs/SWC-113",
    ],
    category: SolidityVulnerabilityCategory.DenialOfService,
    confidence: 80,
  },
];

// ---------------------------------------------------------------------------
// Visibility Patterns
// ---------------------------------------------------------------------------

const visibilityPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-VIS-001",
    name: "Default Visibility on State Variable",
    description:
      "A state variable has no explicit visibility specifier. In Solidity, the default visibility for state variables is 'internal', but relying on defaults reduces code clarity and can mask intentional design decisions.",
    pattern:
      /^\s+(?:uint|int|bool|address|bytes|string|mapping)\s+(?!public|private|internal|external)\w+\s*[;=]/m,
    severity: Severity.Low,
    cvssScore: 3.7,
    cweId: "CWE-710",
    remediation:
      "Always explicitly declare visibility for all state variables (public, private, internal). This improves readability and makes the intended access pattern clear.",
    references: [
      "https://swcregistry.io/docs/SWC-108",
    ],
    category: SolidityVulnerabilityCategory.Visibility,
    confidence: 50,
  },
];

// ---------------------------------------------------------------------------
// Deprecated Feature Patterns
// ---------------------------------------------------------------------------

const deprecatedPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-DEPR-001",
    name: "Use of Deprecated suicide() Function",
    description:
      "The contract uses the deprecated suicide() function instead of selfdestruct(). While functionally identical, suicide() was renamed for clarity and may be removed in future compiler versions.",
    pattern:
      /\bsuicide\s*\(/m,
    severity: Severity.Low,
    cvssScore: 3.7,
    cweId: "CWE-477",
    remediation:
      "Replace suicide() with selfdestruct(). Better yet, remove selfdestruct entirely if not needed.",
    references: [
      "https://swcregistry.io/docs/SWC-106",
    ],
    category: SolidityVulnerabilityCategory.DeprecatedFeature,
    confidence: 95,
  },
  {
    id: "SOL-DEPR-002",
    name: "Use of Deprecated throw Statement",
    description:
      "The contract uses the deprecated 'throw' statement. In Solidity >=0.5.0, throw was removed. Use require(), revert(), or assert() instead.",
    pattern:
      /\bthrow\s*;/m,
    severity: Severity.Low,
    cvssScore: 3.7,
    cweId: "CWE-477",
    remediation:
      "Replace throw with require(condition, \"message\") for input validation, revert(\"message\") for general reverts, or assert(condition) for invariant checks.",
    references: [
      "https://docs.soliditylang.org/en/v0.8.0/050-breaking-changes.html",
    ],
    category: SolidityVulnerabilityCategory.DeprecatedFeature,
    confidence: 95,
  },
  {
    id: "SOL-DEPR-003",
    name: "Use of block.blockhash (Deprecated)",
    description:
      "The contract uses the deprecated block.blockhash() syntax instead of the built-in blockhash() function.",
    pattern:
      /block\.blockhash\s*\(/m,
    severity: Severity.Low,
    cvssScore: 3.7,
    cweId: "CWE-477",
    remediation:
      "Replace block.blockhash(blockNumber) with blockhash(blockNumber).",
    references: [
      "https://docs.soliditylang.org/en/latest/units-and-global-variables.html",
    ],
    category: SolidityVulnerabilityCategory.DeprecatedFeature,
    confidence: 95,
  },
];

// ---------------------------------------------------------------------------
// Flash Loan / Price Manipulation Patterns
// ---------------------------------------------------------------------------

const flashLoanPatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-FLASH-001",
    name: "Spot Price Used as Oracle (Flash Loan Risk)",
    description:
      "The contract reads token balances or reserves directly from a DEX pool (getReserves, balanceOf on pool address) to determine prices. This is vulnerable to flash loan attacks where an attacker can temporarily manipulate pool balances within a single transaction.",
    pattern:
      /(?:getReserves|balanceOf)\s*\([^)]*\)[^;]*(?:price|rate|value|amount|ratio)/im,
    severity: Severity.High,
    cvssScore: 8.1,
    cweId: "CWE-829",
    remediation:
      "Use time-weighted average prices (TWAP) from Uniswap V3 or a decentralized oracle like Chainlink Price Feeds. Never use spot prices from DEX pools for critical operations.",
    references: [
      "https://www.euler.finance/blog/euler-notes-1",
      "https://docs.chain.link/data-feeds",
    ],
    category: SolidityVulnerabilityCategory.OracleManipulation,
    confidence: 55,
  },
];

// ---------------------------------------------------------------------------
// Signature Replay Patterns
// ---------------------------------------------------------------------------

const signaturePatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-SIG-001",
    name: "Missing Nonce in Signature Verification",
    description:
      "The contract verifies signatures (ecrecover or ECDSA.recover) without including a nonce or deadline. A valid signature can be replayed multiple times or used across different chains (if chain ID is not included).",
    pattern:
      /ecrecover\s*\(|ECDSA\.recover\s*\(/m,
    severity: Severity.High,
    cvssScore: 7.5,
    cweId: "CWE-347",
    remediation:
      "Include a nonce, chain ID (block.chainid), contract address, and deadline in all signed messages. Increment the nonce after each use. Follow EIP-712 for typed structured data hashing and signing.",
    references: [
      "https://swcregistry.io/docs/SWC-121",
      "https://eips.ethereum.org/EIPS/eip-712",
    ],
    category: SolidityVulnerabilityCategory.SignatureReplay,
    confidence: 60,
  },
];

// ---------------------------------------------------------------------------
// Storage Collision Patterns
// ---------------------------------------------------------------------------

const storagePatterns: SolidityVulnerabilityPattern[] = [
  {
    id: "SOL-STORAGE-001",
    name: "Storage Collision Risk in Proxy Contract",
    description:
      "The contract uses delegatecall with a custom storage layout that may collide with the proxy's storage slots. Inherited state variables in the proxy and implementation must be aligned, or explicit storage slots (EIP-1967) must be used.",
    pattern:
      /(?:StorageSlot|sload|sstore)\s*\(|bytes32\s+(?:private|internal)\s+constant\s+\w+\s*=\s*(?:keccak256|bytes32)\(/m,
    severity: Severity.High,
    cvssScore: 8.1,
    cweId: "CWE-787",
    remediation:
      "Use EIP-1967 storage slots for proxy-related state (implementation address, admin, beacon). Use OpenZeppelin's TransparentUpgradeableProxy or UUPS proxy contracts. Never modify the storage layout of an upgradeable contract; only append new variables.",
    references: [
      "https://eips.ethereum.org/EIPS/eip-1967",
      "https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies",
    ],
    category: SolidityVulnerabilityCategory.StorageCollision,
    confidence: 50,
  },
];

// ---------------------------------------------------------------------------
// Consolidated Pattern Database
// ---------------------------------------------------------------------------

/** All vulnerability patterns organized by category. */
export const PATTERN_DATABASE: SolidityVulnerabilityPattern[] = [
  ...reentrancyPatterns,
  ...integerPatterns,
  ...accessControlPatterns,
  ...uncheckedCallPatterns,
  ...txOriginPatterns,
  ...delegatecallPatterns,
  ...selfDestructPatterns,
  ...timestampPatterns,
  ...randomnessPatterns,
  ...dosPatterns,
  ...visibilityPatterns,
  ...deprecatedPatterns,
  ...flashLoanPatterns,
  ...signaturePatterns,
  ...storagePatterns,
];

/**
 * Returns patterns filtered by category.
 */
export function getPatternsByCategory(
  category: SolidityVulnerabilityCategory,
): SolidityVulnerabilityPattern[] {
  return PATTERN_DATABASE.filter((p) => p.category === category);
}

/**
 * Returns patterns filtered by minimum severity.
 */
export function getPatternsBySeverity(
  minSeverity: Severity,
): SolidityVulnerabilityPattern[] {
  const weight: Record<Severity, number> = {
    [Severity.Critical]: 5,
    [Severity.High]: 4,
    [Severity.Medium]: 3,
    [Severity.Low]: 2,
    [Severity.Info]: 1,
  };

  const minWeight = weight[minSeverity];
  return PATTERN_DATABASE.filter((p) => weight[p.severity] >= minWeight);
}

/**
 * Returns a single pattern by its ID, or undefined.
 */
export function getPatternById(
  id: string,
): SolidityVulnerabilityPattern | undefined {
  return PATTERN_DATABASE.find((p) => p.id === id);
}
