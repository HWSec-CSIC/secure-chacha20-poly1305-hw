// =============================================================================
// chacha20_qr.sv
// Quarter-Round (QR) Function for ChaCha20
// Shared module used by both the standard and secure architectures.
// =============================================================================
//
// Implements the ChaCha20 quarter-round operation:
//   a += b; d ^= a; d <<<= 16;
//   c += d; b ^= c; b <<<= 12;
//   a += b; d ^= a; d <<<= 8;
//   c += d; b ^= c; b <<<= 7;
//
// =============================================================================

`timescale 1ns / 1ps

module chacha20_qr (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        en,
    input  logic [31:0] a_in,
    input  logic [31:0] b_in,
    input  logic [31:0] c_in,
    input  logic [31:0] d_in,
    output logic [31:0] a_out,
    output logic [31:0] b_out,
    output logic [31:0] c_out,
    output logic [31:0] d_out,
    output logic        valid
);

    // Internal wires for each sub-step
    logic [31:0] a1, b1, c1, d1;
    logic [31:0] a2, b2, c2, d2;
    logic [31:0] a3, b3, c3, d3;
    logic [31:0] a4, b4, c4, d4;

    // Pipeline valid shift register
    logic [3:0] valid_sr;

    // --- Sub-step 1: a += b; d ^= a; d <<<= 16 ---
    assign a1 = a_in + b_in;
    assign d1 = {(d_in ^ a1)[15:0], (d_in ^ a1)[31:16]};
    assign b1 = b_in;
    assign c1 = c_in;

    // --- Sub-step 2: c += d; b ^= c; b <<<= 12 ---
    assign c2 = c1 + d1;
    assign b2 = {(b1 ^ c2)[19:0], (b1 ^ c2)[31:20]};
    assign a2 = a1;
    assign d2 = d1;

    // --- Sub-step 3: a += b; d ^= a; d <<<= 8 ---
    assign a3 = a2 + b2;
    assign d3 = {(d2 ^ a3)[23:0], (d2 ^ a3)[31:24]};
    assign b3 = b2;
    assign c3 = c2;

    // --- Sub-step 4: c += d; b ^= c; b <<<= 7 ---
    assign c4 = c3 + d3;
    assign b4 = {(b3 ^ c4)[24:0], (b3 ^ c4)[31:25]};
    assign a4 = a3;
    assign d4 = d3;

    // Registered outputs
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            a_out    <= 32'd0;
            b_out    <= 32'd0;
            c_out    <= 32'd0;
            d_out    <= 32'd0;
            valid_sr <= 4'd0;
        end else if (en) begin
            a_out    <= a4;
            b_out    <= b4;
            c_out    <= c4;
            d_out    <= d4;
            valid_sr <= {valid_sr[2:0], 1'b1};
        end else begin
            valid_sr <= {valid_sr[2:0], 1'b0};
        end
    end

    assign valid = valid_sr[0];

endmodule
