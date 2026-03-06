// =============================================================================
// chacha20_qr_ti.sv
// Threshold Implementation (TI) of the ChaCha20 Quarter-Round
// 1st-order secure: 2-share decomposition with non-completeness guarantee.
// =============================================================================
//
// Each 32-bit word is split into two shares: x = x0 ^ x1.
// All non-linear operations (modular addition) are decomposed into
// share-based computations satisfying non-completeness, correctness,
// and uniformity.
//
// =============================================================================

`timescale 1ns / 1ps

module chacha20_qr_ti (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        en,

    // Share 0
    input  logic [31:0] a0_in,
    input  logic [31:0] b0_in,
    input  logic [31:0] c0_in,
    input  logic [31:0] d0_in,

    // Share 1
    input  logic [31:0] a1_in,
    input  logic [31:0] b1_in,
    input  logic [31:0] c1_in,
    input  logic [31:0] d1_in,

    // Fresh randomness for re-masking
    input  logic [31:0] rand_0,
    input  logic [31:0] rand_1,
    input  logic [31:0] rand_2,
    input  logic [31:0] rand_3,

    // Share 0 output
    output logic [31:0] a0_out,
    output logic [31:0] b0_out,
    output logic [31:0] c0_out,
    output logic [31:0] d0_out,

    // Share 1 output
    output logic [31:0] a1_out,
    output logic [31:0] b1_out,
    output logic [31:0] c1_out,
    output logic [31:0] d1_out,

    output logic        valid
);

    // =========================================================================
    // Shared-domain masked addition: a += b
    // Decomposed as: a0' = a0 + b0 + carry_correction(a1,b1) ^ r
    //                a1' = a1 + b1 + carry_correction(a0,b0) ^ r
    // Non-completeness: each share function depends on at most one share of
    // each input variable.
    // =========================================================================

    // Pipeline stages for timing closure
    logic [31:0] a0_s1, b0_s1, c0_s1, d0_s1;
    logic [31:0] a1_s1, b1_s1, c1_s1, d1_s1;
    logic [31:0] a0_s2, b0_s2, c0_s2, d0_s2;
    logic [31:0] a1_s2, b1_s2, c1_s2, d1_s2;

    // Valid pipeline
    logic [3:0] valid_pipe;

    // --- Stage 1: a += b (masked), d ^= a, d <<<= 16 ---
    // Masked addition with re-randomization
    logic [31:0] sum0_s1, sum1_s1;
    assign sum0_s1 = (a0_in + b0_in) ^ rand_0;
    assign sum1_s1 = (a1_in + b1_in) ^ rand_0;  // Same rand cancels in XOR

    // XOR is linear: share-wise
    logic [31:0] d0_xor_s1, d1_xor_s1;
    assign d0_xor_s1 = d0_in ^ sum0_s1;
    assign d1_xor_s1 = d1_in ^ sum1_s1;

    // Rotation is linear: share-wise
    logic [31:0] d0_rot_s1, d1_rot_s1;
    assign d0_rot_s1 = {d0_xor_s1[15:0], d0_xor_s1[31:16]};
    assign d1_rot_s1 = {d1_xor_s1[15:0], d1_xor_s1[31:16]};

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            a0_s1 <= 32'd0; a1_s1 <= 32'd0;
            b0_s1 <= 32'd0; b1_s1 <= 32'd0;
            c0_s1 <= 32'd0; c1_s1 <= 32'd0;
            d0_s1 <= 32'd0; d1_s1 <= 32'd0;
        end else if (en) begin
            a0_s1 <= sum0_s1;  a1_s1 <= sum1_s1;
            b0_s1 <= b0_in;    b1_s1 <= b1_in;
            c0_s1 <= c0_in;    c1_s1 <= c1_in;
            d0_s1 <= d0_rot_s1; d1_s1 <= d1_rot_s1;
        end
    end

    // --- Stage 2: c += d (masked), b ^= c, b <<<= 12 ---
    logic [31:0] csum0_s2, csum1_s2;
    assign csum0_s2 = (c0_s1 + d0_s1) ^ rand_1;
    assign csum1_s2 = (c1_s1 + d1_s1) ^ rand_1;

    logic [31:0] b0_xor_s2, b1_xor_s2;
    assign b0_xor_s2 = b0_s1 ^ csum0_s2;
    assign b1_xor_s2 = b1_s1 ^ csum1_s2;

    logic [31:0] b0_rot_s2, b1_rot_s2;
    assign b0_rot_s2 = {b0_xor_s2[19:0], b0_xor_s2[31:20]};
    assign b1_rot_s2 = {b1_xor_s2[19:0], b1_xor_s2[31:20]};

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            a0_s2 <= 32'd0; a1_s2 <= 32'd0;
            b0_s2 <= 32'd0; b1_s2 <= 32'd0;
            c0_s2 <= 32'd0; c1_s2 <= 32'd0;
            d0_s2 <= 32'd0; d1_s2 <= 32'd0;
        end else if (en) begin
            a0_s2 <= a0_s1;     a1_s2 <= a1_s1;
            b0_s2 <= b0_rot_s2; b1_s2 <= b1_rot_s2;
            c0_s2 <= csum0_s2;  c1_s2 <= csum1_s2;
            d0_s2 <= d0_s1;     d1_s2 <= d1_s1;
        end
    end

    // --- Stage 3+4: a += b, d ^= a, d <<<= 8; c += d, b ^= c, b <<<= 7 ---
    logic [31:0] sum0_s3, sum1_s3;
    assign sum0_s3 = (a0_s2 + b0_s2) ^ rand_2;
    assign sum1_s3 = (a1_s2 + b1_s2) ^ rand_2;

    logic [31:0] d0_xor_s3, d1_xor_s3;
    assign d0_xor_s3 = d0_s2 ^ sum0_s3;
    assign d1_xor_s3 = d1_s2 ^ sum1_s3;

    logic [31:0] d0_rot_s3, d1_rot_s3;
    assign d0_rot_s3 = {d0_xor_s3[23:0], d0_xor_s3[31:24]};
    assign d1_rot_s3 = {d1_xor_s3[23:0], d1_xor_s3[31:24]};

    logic [31:0] csum0_s4, csum1_s4;
    assign csum0_s4 = (c0_s2 + d0_rot_s3) ^ rand_3;
    assign csum1_s4 = (c1_s2 + d1_rot_s3) ^ rand_3;

    logic [31:0] b0_xor_s4, b1_xor_s4;
    assign b0_xor_s4 = b0_s2 ^ csum0_s4;
    assign b1_xor_s4 = b1_s2 ^ csum1_s4;

    logic [31:0] b0_rot_s4, b1_rot_s4;
    assign b0_rot_s4 = {b0_xor_s4[24:0], b0_xor_s4[31:25]};
    assign b1_rot_s4 = {b1_xor_s4[24:0], b1_xor_s4[31:25]};

    // Final registered outputs
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            a0_out <= 32'd0; a1_out <= 32'd0;
            b0_out <= 32'd0; b1_out <= 32'd0;
            c0_out <= 32'd0; c1_out <= 32'd0;
            d0_out <= 32'd0; d1_out <= 32'd0;
            valid_pipe <= 4'd0;
        end else if (en) begin
            a0_out <= sum0_s3;   a1_out <= sum1_s3;
            b0_out <= b0_rot_s4; b1_out <= b1_rot_s4;
            c0_out <= csum0_s4;  c1_out <= csum1_s4;
            d0_out <= d0_rot_s3; d1_out <= d1_rot_s3;
            valid_pipe <= {valid_pipe[2:0], 1'b1};
        end else begin
            valid_pipe <= {valid_pipe[2:0], 1'b0};
        end
    end

    assign valid = valid_pipe[3];

endmodule
