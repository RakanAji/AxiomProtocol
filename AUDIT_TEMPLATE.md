# 1. About [Auditor Name]

[Masukkan deskripsi singkat tentang perusahaan audit atau auditor individu di sini. Jelaskan metodologi, keahlian, dan layanan yang ditawarkan.]

Learn more about us at [Website Link].

# 2. Disclaimer

This security review does not guarantee bulletproof protection against a hack or exploit. Smart contracts are a novel technological feat with many known and unknown risks. The protocol, which this report is intended for, indemnifies [Auditor Name] against any responsibility for any misbehavior, bugs, or exploits affecting the audited code during any part of the project's life cycle. It is also pivotal to acknowledge that modifications made to the audited code, including fixes for the issues described in this report, may introduce new problems and necessitate additional auditing.

# 3. About [Project Name]

[Masukkan deskripsi singkat tentang protokol yang diaudit. Jelaskan fungsi utamanya, tujuan bisnis, dan arsitekturnya.]

Learn more about [Project Name] concept and technical details: [Link to Project Docs]

# 4. Risk Classification

|        Severity        | Impact: High | Impact: Medium | Impact: Low |
| :--------------------: | :----------: | :------------: | :---------: |
|  **Likelihood: High** |   Critical   |      High      |   Medium    |
| **Likelihood: Medium** |     High     |     Medium     |     Low     |
|  **Likelihood: Low** |    Medium    |      Low       |     Low     |

## 4.1 Impact

- **High** - results in a significant risk for the protocol’s overall well-being. Affects all or most users.
- **Medium** - results in a non-critical risk for the protocol affects all or only a subset of users, but is still unacceptable.
- **Low** - losses will be limited but bearable - and covers vectors similar to griefing attacks that can be easily repaired.

## 4.2 Likelihood

- **High** - almost certain to happen and highly lucrative for execution by malicious actors.
- **Medium** - still relatively likely, although only conditionally possible.
- **Low** - requires a unique set of circumstances and poses non-lucrative cost-of-execution to rewards ratio for the actor.

# 5. Security Review Summary

The security review lasted [Number] days with a total of [Number] hours dedicated to the audit by [Auditor Name].

**Executive Summary:**
[Tulis ringkasan eksekutif di sini. Bagaimana kualitas kode secara keseluruhan? Apakah ada pola kerentanan tertentu? Bagaimana respons tim developer?]

## 5.1 Protocol Summary

| **Project Name** | [Project Name]                                                                                                                         |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| **Repository** | [Link to Github Repo]                                                                                                                  |
| **Type of Project** | [e.g., DeFi, NFT, Bridge, etc.]                                                                                                        |
| **Security Review Timeline** | [Start Date] to [End Date]                                                                                                             |
| **Review Commit Hash** | [Hash ID](Link to commit)                                                                                                              |
| **Fixes Review Commit Hash** | [Hash ID](Link to commit)                                                                                                              |

## 5.2 Scope

The following smart contracts were in the scope of the security review:

| File              | nSLOC |
| ----------------- | :---: |
| src/ContractA.sol |  100  |
| src/ContractB.sol |  200  |
| **Total** |  **300** |

# 6. Findings Summary

The following number of issues have been identified, sorted by their severity:

- **High** issues: [Number]
- **Medium** issues: [Number]
- **Low** issues: [Number]
- **Info** issues: [Number]

| **ID** | **Title** | **Severity** |  **Status** |
| :----: | ------------------------------------------------------------------------------------------------------------------------------------------ | :----------: | :----------: |
| [H-01] | [Judul Temuan High 1]                                                                                                                      |     High     |    Fixed     |
| [H-02] | [Judul Temuan High 2]                                                                                                                      |     High     | Acknowledged |
| [M-01] | [Judul Temuan Medium 1]                                                                                                                    |    Medium    |    Fixed     |

# 7. Findings

# [H-01] [Judul Temuan]

## Severity

High Risk

## Description

[Jelaskan konteks masalahnya. Apa yang seharusnya terjadi vs apa yang sebenarnya terjadi. Jelaskan root cause masalahnya.]

### Technical Details

[Jelaskan secara teknis, langkah demi langkah logika yang salah.]

## Location of Affected Code

File: [FileName.sol](Link to File)

```solidity
function example() public {
    // Paste affected code snippet here
    bug_is_here();
}