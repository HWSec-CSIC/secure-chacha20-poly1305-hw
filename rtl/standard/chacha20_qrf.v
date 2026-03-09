`default_nettype none
// Combinational quarter-round function for ChaCha20 (ARX operations).

module chacha_qr_comb (
    input  wire        enable,
    input  wire [31:0] a_in,
    input  wire [31:0] b_in,
    input  wire [31:0] c_in,
    input  wire [31:0] d_in,
    output wire [31:0] a_out,
    output wire [31:0] b_out,
    output wire [31:0] c_out,
    output wire [31:0] d_out
);

  // Quarter-round ARX steps
  wire [31:0] a0 = a_in + b_in;
  wire [31:0] d0 = d_in ^ a0;
  wire [31:0] d1 = {d0[15:0], d0[31:16]}; // Rotate left 16

  wire [31:0] c0 = c_in + d1;
  wire [31:0] b0 = b_in ^ c0;
  wire [31:0] b1 = {b0[19:0], b0[31:20]}; // Rotate left 12

  wire [31:0] a1 = a0 + b1;
  wire [31:0] d2 = d1 ^ a1;
  wire [31:0] d3 = {d2[23:0], d2[31:24]}; // Rotate left 8

  wire [31:0] c1 = c0 + d3;
  wire [31:0] b2 = b1 ^ c1;
  wire [31:0] b3 = {b2[24:0], b2[31:25]}; // Rotate left 7

  // Assign results
  assign a_out = enable ? a1 : a_in;
  assign b_out = enable ? b3 : b_in;
  assign c_out = enable ? c1 : c_in;
  assign d_out = enable ? d3 : d_in;

endmodule
