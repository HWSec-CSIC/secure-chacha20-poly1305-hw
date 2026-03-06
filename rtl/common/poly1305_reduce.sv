// =============================================================================
// poly1305_reduce.sv
// Modular Reduction for Poly1305 (mod 2^130 - 5)
// Shared module used by both the standard and secure architectures.
// =============================================================================

`timescale 1ns / 1ps

module poly1305_reduce (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        en,
    input  logic [259:0] product_in,   // Up to 260-bit product from multiplier
    output logic [129:0] reduced_out,  // 130-bit reduced result
    output logic         valid
);

    // Poly1305 prime: p = 2^130 - 5
    // Reduction: if X = X_hi * 2^130 + X_lo, then X mod p = X_lo + 5 * X_hi

    logic [129:0] x_lo;
    logic [131:0] x_hi;       // Upper bits (up to 130 bits shifted)
    logic [134:0] x_hi_times5;
    logic [130:0] sum;
    logic [129:0] result;

    // Split product
    assign x_lo = product_in[129:0];
    assign x_hi = product_in[259:130];

    // Multiply high part by 5
    assign x_hi_times5 = x_hi * 3'd5;

    // Add
    assign sum = {1'b0, x_lo} + x_hi_times5[130:0];

    // Final conditional subtraction (if sum >= 2^130 - 5)
    logic [130:0] p_const;
    assign p_const = (131'd1 << 130) - 131'd5;

    logic overflow;
    assign overflow = (sum >= p_const);

    assign result = overflow ? sum[129:0] - p_const[129:0] + (sum[130] ? 130'd5 : 130'd0)
                             : sum[129:0];

    // Registered output
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            reduced_out <= 130'd0;
            valid       <= 1'b0;
        end else if (en) begin
            reduced_out <= result;
            valid       <= 1'b1;
        end else begin
            valid       <= 1'b0;
        end
    end

endmodule
