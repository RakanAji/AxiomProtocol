// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Pairing
 * @author Axiom Protocol Team (adapted from SnarkJS Groth16 template)
 * @notice Library for BN254 (alt_bn128) elliptic curve pairing operations
 * @dev BN254 is the curve used by Ethereum's precompiled contracts for pairing checks.
 *
 *      === HOW THE MATH WORKS (for the curious) ===
 *
 *      BN254 defines two groups of points on an elliptic curve:
 *        - G1: Points (x, y) where x, y are elements of F_p (a prime field)
 *        - G2: Points (x, y) where x, y are elements of F_p² (a quadratic extension field)
 *                → That's why G2 points use [2][2] arrays: each coordinate has 2 components
 *
 *      The "pairing" operation e(P, Q) takes a G1 point P and a G2 point Q and produces
 *      an element in a target group GT (think of it as a special "fingerprint").
 *
 *      Key property: e(a·P, Q) == e(P, a·Q) — this is called BILINEARITY.
 *      This property is what makes ZK-SNARKs possible.
 *
 *      Ethereum provides three precompiled contracts for BN254:
 *        - 0x06: EC point addition on G1
 *        - 0x07: EC scalar multiplication on G1
 *        - 0x08: Pairing check (the expensive one, ~45k gas per pair)
 */
library Pairing {
    // ═══════════════════════════════════════════════════════════════════════════
    //                              TYPES
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice A point on the G1 curve (x, y ∈ F_p)
    /// @dev The point at infinity (identity element) is represented as (0, 0)
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    /// @notice A point on the G2 curve (x, y ∈ F_p²)
    /// @dev Each coordinate is an element of F_p² = F_p[i]/(i² + 1),
    ///      represented as two uint256 values: [real, imaginary]
    ///      IMPORTANT: The ordering is [imaginary, real] to match the EVM precompile
    struct G2Point {
        uint256[2] X; // [X_im, X_re]
        uint256[2] Y; // [Y_im, Y_re]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          CURVE CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════════

    /// @dev Prime field modulus p for BN254
    ///      All G1 coordinates live in F_p = {0, 1, ..., p-1}
    uint256 internal constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // ═══════════════════════════════════════════════════════════════════════════
    //                          G1 OPERATIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Negate a G1 point: if P = (x, y), then -P = (x, p - y)
     * @dev On an elliptic curve, negation reflects the point across the x-axis.
     *      This is used to construct the pairing equation: instead of checking
     *      e(A, B) == e(C, D), we check e(A, B) · e(-C, D) == 1 (identity)
     * @param p1 The point to negate
     * @return The negated point
     */
    function negate(G1Point memory p1) internal pure returns (G1Point memory) {
        if (p1.X == 0 && p1.Y == 0) {
            return G1Point(0, 0); // Point at infinity is its own negation
        }
        return G1Point(p1.X, PRIME_Q - (p1.Y % PRIME_Q));
    }

    /**
     * @notice Add two G1 points using the EVM precompile at address 0x06
     * @dev Elliptic curve point addition: R = P + Q
     *      Uses the chord-and-tangent rule on the curve y² = x³ + 3
     *      Gas cost: ~150 gas via precompile (vs ~10,000 in pure Solidity)
     * @param p1 First point
     * @param p2 Second point
     * @return r The sum point P + Q
     */
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;

        bool success;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Call precompile at address 0x06 (EC_ADD)
            // Input: 128 bytes (two 64-byte points)
            // Output: 64 bytes (one point)
            success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
        }
        require(success, "Pairing: G1 addition failed");
    }

    /**
     * @notice Multiply a G1 point by a scalar using the EVM precompile at address 0x07
     * @dev Computes s·P using double-and-add algorithm (inside the precompile)
     *      This is used to compute IC[0] + input[0]·IC[1] + input[1]·IC[2] + ...
     *      which constructs the "public input commitment" for the pairing check
     * @param p The base point
     * @param s The scalar multiplier
     * @return r The product s·P
     */
    function scalarMul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;

        bool success;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Call precompile at address 0x07 (EC_MUL)
            // Input: 96 bytes (one 64-byte point + 32-byte scalar)
            // Output: 64 bytes (one point)
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
        }
        require(success, "Pairing: G1 scalar multiplication failed");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //                          PAIRING CHECK
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Check if a set of pairing equations holds: ∏ e(p1[i], p2[i]) == 1
     * @dev This is THE core operation of Groth16 verification.
     *
     *      The pairing precompile (0x08) takes N pairs of (G1, G2) points and checks:
     *        e(P1, Q1) · e(P2, Q2) · ... · e(Pn, Qn) == 1  (in GT)
     *
     *      Returns true if the product of all pairings equals the identity element.
     *      Gas cost: ~34,000 base + ~45,000 per pair
     *
     * @param p1 Array of G1 points
     * @param p2 Array of G2 points (same length as p1)
     * @return True if the pairing equation holds
     */
    function pairing(
        G1Point[] memory p1,
        G2Point[] memory p2
    ) internal view returns (bool) {
        require(p1.length == p2.length, "Pairing: unequal lengths");

        uint256 elements = p1.length;
        uint256 inputSize = elements * 6; // Each pair = 6 uint256s (2 for G1 + 4 for G2)

        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].X;
            input[j + 1] = p1[i].Y;
            input[j + 2] = p2[i].X[0]; // G2.X imaginary
            input[j + 3] = p2[i].X[1]; // G2.X real
            input[j + 4] = p2[i].Y[0]; // G2.Y imaginary
            input[j + 5] = p2[i].Y[1]; // G2.Y real
        }

        uint256[1] memory out;
        bool success;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Call precompile at address 0x08 (EC_PAIRING)
            // Input: N * 192 bytes (N pairs of points)
            // Output: 32 bytes (0 or 1)
            success := staticcall(
                sub(gas(), 2000),
                8,
                add(input, 0x20),    // skip array length prefix
                mul(inputSize, 0x20), // total bytes = elements * 6 * 32
                out,
                0x20
            )
        }
        require(success, "Pairing: pairing check failed");
        return out[0] != 0;
    }
}

/**
 * @title Groth16Verifier
 * @author Axiom Protocol Team
 * @notice Standard Groth16 ZK-SNARK verifier for BN254 curve
 * @dev This contract verifies proofs generated by snarkjs/circom for the
 *      Axiom Privacy circuit. The verification key constants below are
 *      PLACEHOLDERS — in production, they would be generated from a real
 *      trusted setup ceremony.
 *
 *      === GROTH16 VERIFICATION EQUATION ===
 *
 *      A Groth16 proof consists of three elliptic curve points: (A, B, C)
 *      where A ∈ G1, B ∈ G2, C ∈ G1.
 *
 *      The verification key consists of:
 *        - α (alpha) ∈ G1  — from trusted setup
 *        - β (beta)  ∈ G2  — from trusted setup
 *        - γ (gamma) ∈ G2  — from trusted setup
 *        - δ (delta) ∈ G2  — from trusted setup
 *        - IC[0..n]  ∈ G1  — "input commitments", one per public input + 1
 *
 *      The prover must convince the verifier that they know secret values
 *      (witnesses) that satisfy the circuit constraints, WITHOUT revealing them.
 *
 *      The verification equation is:
 *
 *        e(A, B) == e(α, β) · e(vk_x, γ) · e(C, δ)
 *
 *      where vk_x = IC[0] + Σ(input[i] · IC[i+1])
 *
 *      Rearranged for the pairing precompile (product must equal 1):
 *
 *        e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
 *
 *      If this equation holds, the proof is valid — meaning the prover
 *      indeed knows the secret witness values.
 *
 *      === WHY THIS IS SECURE ===
 *
 *      The security relies on:
 *      1. The hardness of the Discrete Logarithm Problem on BN254
 *      2. The trusted setup ceremony producing toxic waste that is destroyed
 *      3. The bilinear property of pairings: e(a·G, b·H) = e(G, H)^(ab)
 *
 *      A forger cannot produce valid (A, B, C) without knowing the witnesses
 *      because they'd need to solve the discrete log problem.
 *
 *      Expected public inputs for this circuit:
 *        - input[0]: commitment  (hash of address + secret + nullifier)
 *        - input[1]: nullifierHash (hash of nullifier + contentHash)
 *        - input[2]: contentHash (SHA-256 of the content)
 */
contract Groth16Verifier {
    using Pairing for *;

    // ═══════════════════════════════════════════════════════════════════════════
    //                      VERIFICATION KEY (PLACEHOLDER)
    // ═══════════════════════════════════════════════════════════════════════════
    //
    //  In production, these values are generated by:
    //    1. Writing a Circom circuit (e.g., commitment_verifier.circom)
    //    2. Running a trusted setup: snarkjs groth16 setup circuit.r1cs pot_final.ptau circuit.zkey
    //    3. Exporting the verification key: snarkjs zkey export solidityverifier circuit.zkey Verifier.sol
    //
    //  The values below are STRUCTURALLY CORRECT placeholder points on BN254.
    //  They use the generator points G1 = (1, 2) and G2 = (known generator coords).

    /// @notice Alpha point (G1) — part of the trusted setup
    /// @dev α encodes part of the CRS (Common Reference String)
    function _alpha1() internal pure returns (Pairing.G1Point memory) {
        return Pairing.G1Point(
            1, // G1 generator x-coordinate
            2  // G1 generator y-coordinate
        );
    }

    /// @notice Beta point (G2) — part of the trusted setup
    /// @dev β is paired with α to form the "reference pairing" e(α, β)
    function _beta2() internal pure returns (Pairing.G2Point memory) {
        return Pairing.G2Point(
            [
                11559732032986387107991004021392285783925812861821192530917403151452391805634,
                10857046999023057135944570762232829481370756359578518086990519993285655852781
            ],
            [
                4082367875863433681332203403145435568316851327593401208105741076214120093531,
                8495653923123431417604973247489272438418190587263600148770280649306958101930
            ]
        );
    }

    /// @notice Gamma point (G2) — used to verify public inputs
    /// @dev The public input commitment vk_x is paired with γ
    function _gamma2() internal pure returns (Pairing.G2Point memory) {
        return Pairing.G2Point(
            [
                11559732032986387107991004021392285783925812861821192530917403151452391805634,
                10857046999023057135944570762232829481370756359578518086990519993285655852781
            ],
            [
                4082367875863433681332203403145435568316851327593401208105741076214120093531,
                8495653923123431417604973247489272438418190587263600148770280649306958101930
            ]
        );
    }

    /// @notice Delta point (G2) — used to verify the proof element C
    /// @dev δ ensures the proof was constructed with knowledge of the witness
    function _delta2() internal pure returns (Pairing.G2Point memory) {
        return Pairing.G2Point(
            [
                11559732032986387107991004021392285783925812861821192530917403151452391805634,
                10857046999023057135944570762232829481370756359578518086990519993285655852781
            ],
            [
                4082367875863433681332203403145435568316851327593401208105741076214120093531,
                8495653923123431417604973247489272438418190587263600148770280649306958101930
            ]
        );
    }

    /**
     * @notice Input Commitment points (IC) — one per public input + 1
     * @dev IC[0] is the base point; IC[1..n] correspond to each public input.
     *      vk_x = IC[0] + input[0]·IC[1] + input[1]·IC[2] + input[2]·IC[3]
     *
     *      For our 3-input circuit (commitment, nullifierHash, contentHash), we need 4 IC points.
     *      These are placeholder G1 generator points.
     */
    function _IC(uint256 index) internal pure returns (Pairing.G1Point memory) {
        if (index == 0) return Pairing.G1Point(1, 2);
        if (index == 1) return Pairing.G1Point(1, 2);
        if (index == 2) return Pairing.G1Point(1, 2);
        if (index == 3) return Pairing.G1Point(1, 2);
        revert("Verifier: IC index out of bounds");
    }

    /// @notice Number of public inputs expected by this circuit
    uint256 public constant NUM_PUBLIC_INPUTS = 3;

    // ═══════════════════════════════════════════════════════════════════════════
    //                          VERIFICATION FUNCTION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Verify a Groth16 proof against the hardcoded verification key
     * @dev This is the main entry point. It performs:
     *      1. Input validation (correct number of public inputs, values in field)
     *      2. Public input commitment: vk_x = IC[0] + Σ(input[i] · IC[i+1])
     *      3. Pairing check: e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
     *
     * @param _pA Proof element A ∈ G1: [x, y] — the prover's first point
     * @param _pB Proof element B ∈ G2: [[x_im, x_re], [y_im, y_re]] — the prover's second point
     * @param _pC Proof element C ∈ G1: [x, y] — the prover's third point
     * @param _pubSignals Public inputs to the circuit [commitment, nullifierHash, contentHash]
     * @return True if the proof is valid
     */
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata _pubSignals
    ) public view returns (bool) {
        // ── Step 1: Validate Input Count ──
        // The circuit expects exactly NUM_PUBLIC_INPUTS public signals
        require(
            _pubSignals.length == NUM_PUBLIC_INPUTS,
            "Verifier: invalid number of public inputs"
        );

        // ── Step 2: Validate Input Field Membership ──
        // All public inputs must be elements of the scalar field (< SNARK_SCALAR_FIELD)
        // This prevents overflow attacks where an attacker could wrap around the field
        uint256 SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        for (uint256 i = 0; i < _pubSignals.length; i++) {
            require(
                _pubSignals[i] < SNARK_SCALAR_FIELD,
                "Verifier: public input exceeds field size"
            );
        }

        // ── Step 3: Compute Public Input Commitment (vk_x) ──
        // vk_x = IC[0] + input[0]·IC[1] + input[1]·IC[2] + input[2]·IC[3]
        //
        // This "encodes" the public inputs into a single G1 point so they can
        // participate in the pairing equation. Each IC[i] is a fixed point from
        // the trusted setup that corresponds to the i-th wire of the circuit.
        Pairing.G1Point memory vk_x = _IC(0);
        for (uint256 i = 0; i < _pubSignals.length; i++) {
            vk_x = Pairing.addition(
                vk_x,
                Pairing.scalarMul(_IC(i + 1), _pubSignals[i])
            );
        }

        // ── Step 4: Construct Proof Points ──
        // Convert the calldata arrays into structured G1/G2 points
        Pairing.G1Point memory pA = Pairing.G1Point(_pA[0], _pA[1]);
        Pairing.G2Point memory pB = Pairing.G2Point(
            [_pB[0][0], _pB[0][1]],
            [_pB[1][0], _pB[1][1]]
        );
        Pairing.G1Point memory pC = Pairing.G1Point(_pC[0], _pC[1]);

        // ── Step 5: Pairing Check ──
        // Verify: e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
        //
        // Why negate A? The pairing precompile checks if the PRODUCT of all
        // pairings equals 1. The original equation is e(A, B) = e(α, β) · e(vk_x, γ) · e(C, δ).
        // Moving e(A, B) to the other side: e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1.
        Pairing.G1Point[] memory p1 = new Pairing.G1Point[](4);
        Pairing.G2Point[] memory p2 = new Pairing.G2Point[](4);

        // Pair 1: e(-A, B) — negated proof point A with proof point B
        p1[0] = Pairing.negate(pA);
        p2[0] = pB;

        // Pair 2: e(α, β) — the trusted setup reference pairing
        p1[1] = _alpha1();
        p2[1] = _beta2();

        // Pair 3: e(vk_x, γ) — public input commitment with gamma
        p1[2] = vk_x;
        p2[2] = _gamma2();

        // Pair 4: e(C, δ) — proof point C with delta
        p1[3] = pC;
        p2[3] = _delta2();

        // The precompile returns true if: ∏ e(p1[i], p2[i]) == 1 in GT
        return Pairing.pairing(p1, p2);
    }
}
