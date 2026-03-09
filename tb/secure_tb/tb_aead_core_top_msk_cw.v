// =============================================================================
// tb_aead_core_top_msk_cw.v
// Testbench for the DPA-Secure ChaCha20-Poly1305 AEAD Engine
// Verifies functional correctness of the masked datapath and includes
// test vectors for share recombination checks.
// =============================================================================

`timescale 1ns / 1ps

module tb_aead_core_top_msk_cw;     

  // Parameters
  localparam PIPELINE_STAGES = 2;
  localparam CIPHER_ROUNDS   = 20;
  localparam RECURSION_DEPTH = 0;
   
  // input commands
  localparam NO_OP       = 2'b00;
  localparam AAD_NEXT    = 2'b01; 
  localparam PT_NEXT     = 2'b10;
  localparam AEAD_END    = 2'b11;

  // output commands
  localparam NONE         = 2'b00;
  localparam VALID_CT     = 2'b01;
  localparam VALID_MAC    = 2'b10;

  // Clock & reset
  reg           clk = 0;
  reg           rst;

  // Inputs to DUT
  reg           enc, start;
  reg  [1:0]    next_blk;
  reg  [255:0]  key;
  reg  [95:0]   nonce;
  reg  [127:0]  aad, EXP_TAG;
  reg  [511:0]  plaintext;
  reg  [511:0]  PT_1; 
  reg  [511:0]  CT_1;
  reg  [31:0]   AAD_L;
  reg  [31:0]   PT_L; 
   
  reg [11:0] clk_cnt;   

  // Outputs from DUT
  wire [511:0] ciphertext [0:2];
  wire [127:0] tag;
  wire [1:0]   valid;
  wire         ready;

  // Instantiate DUT
  aead_core_top_msk #(
    .PIPELINE_STAGES(PIPELINE_STAGES),
    .CIPHER_ROUNDS(CIPHER_ROUNDS),
    .RECURSION_DEPTH(RECURSION_DEPTH)
  ) dut (
    .clk            (clk),
    .rst            (rst),
    .enc            (enc),
    .start          (start),
    .next_blk       (next_blk),
    .key            (key),
    .nonce          (nonce),
    .aad            (aad),
    .aad_len        (AAD_L),
    .plaintext      (plaintext),
    .pt_len         (PT_L),
    .ciphertext_sh1 (ciphertext[0]),
    .ciphertext_sh2 (ciphertext[1]),
    .ciphertext_sh3 (ciphertext[2]),
    .tag            (tag),
    .valid          (valid),
    .ready          (ready)
  );
   
  initial clk_cnt = 0;

  // Clock generator: 10 ns period
  always #5 clk = ~clk;
   
  always #10 clk_cnt = clk_cnt + 1;

  // RFC 7539 §2.8.2 test vector
  initial begin
    // Load inputs
    enc   = 1;  // encrypt
    key   = 256'h808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F; // Fixed key
    nonce = 96'h070000004041424344454647;
    aad   = 128'h50515253C0C1C2C3C4C5C6C700000000;  // 8-byte AAD + zero padding
    AAD_L = 32'd12;
    PT_L  = 32'd64; // 64 bytes (4 blocks)
    start = 1'b0;
    
    // Full 64-byte plaintext from RFC 
    PT_1 = 512'h4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f;
    
    // Expected ciphertext from RFC (For the given fixed key)
    CT_1 = 512'hd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36;

    // Expected tag from RFC (For the given fixed key)
    EXP_TAG = 128'h57728d89811f44e3449f0d1c25a3e95e;
    
    // --- SYNCHRONIZED RESET ---
    rst = 1; 
    repeat(4) @(posedge clk);
    rst = 0;
    repeat(4) @(posedge clk);
    
    repeat(30) @(posedge clk);
    
    // Pack and load
    plaintext = PT_1;
    // Sequence: absorb AAD, then plaintext. 
    // Use NO_OP to start the automatic sequence from IDLE
    next_blk  = NO_OP;
    
    // Synchronized START pulse
    @(posedge clk); start = 1'b1;
    @(posedge clk); start = 1'b0;
    
    // -----------------------------------------------------
    // 1. WAIT AND VALIDATE CIPHERTEXT (Valid = 01)
    // -----------------------------------------------------
    wait(valid == VALID_CT);
    
    if (ciphertext[0] ^ ciphertext[1] ^ ciphertext[2] === CT_1)
      $display("Ciphertext MATCH");
    else begin
      $display("Ciphertext MISMATCH!");
      $display(" Expected: %h", CT_1);
      $display(" Got     : %h", ciphertext[0]^ciphertext[1]^ciphertext[2] );
    end 
   
    // -----------------------------------------------------
    // 2. WAIT AND VALIDATE TAG (Valid = 10)
    // -----------------------------------------------------
    wait(valid == VALID_MAC);

    if (tag === EXP_TAG)
      $display("Tag MATCH");
    else begin
      $display("Tag MISMATCH!");
      $display(" Expected: %h", EXP_TAG);
      $display(" Got     : %h", tag);
    end
    
    // Wait for HW to finish
    wait(ready);
    #50;
    $finish;
  end

endmodule