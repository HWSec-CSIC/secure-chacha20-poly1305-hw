`default_nettype none
// Masked quarter-round function (3-share TI) with pipelined KSA additions
// and delay lines for latency matching.

module qr_pipelined_ti_3 (
    input  wire          clk,
    input  wire          rst,
    input  wire          run_ksa,
    input  wire [127:0]  rand_bits, 

    // Inputs (3 shares)
    input  wire [31:0]   a_in_1, a_in_2, a_in_3,
    input  wire [31:0]   b_in_1, b_in_2, b_in_3,
    input  wire [31:0]   c_in_1, c_in_2, c_in_3,
    input  wire [31:0]   d_in_1, d_in_2, d_in_3,

    // Outputs (3 shares)
    output wire [31:0]   a_out_1, a_out_2, a_out_3,
    output wire [31:0]   b_out_1, b_out_2, b_out_3,
    output wire [31:0]   c_out_1, c_out_2, c_out_3,
    output wire [31:0]   d_out_1, d_out_2, d_out_3
);

    // KSA latency: N_BITS=32 -> N_STAGES=5
    localparam ADDER_LATENCY = 6; 

    // --- Stage 1: a += b; d ^= a; d <<<= 16 ---
    wire [31:0] s1_a_sum_1, s1_a_sum_2, s1_a_sum_3;
    
    // A = A + B
    ksa_ti_3 #(.N_BITS(32)) adder_stg1 (
        .clk(clk), .rst(rst), .run(run_ksa),
        .rand_bits(rand_bits[31:0]),
        .a_in_1(a_in_1), .a_in_2(a_in_2), .a_in_3(a_in_3),
        .b_in_1(b_in_1), .b_in_2(b_in_2), .b_in_3(b_in_3),
        .s_out_1(s1_a_sum_1), .s_out_2(s1_a_sum_2), .s_out_3(s1_a_sum_3)
    );

    // Delay C, D, B while waiting for adder
    wire [31:0] s1_c_dly_1, s1_c_dly_2, s1_c_dly_3;
    wire [31:0] s1_d_dly_1, s1_d_dly_2, s1_d_dly_3;
    wire [31:0] s1_b_dly_1, s1_b_dly_2, s1_b_dly_3;

    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg1_c (
        .clk(clk), .rst(rst),
        .in1(c_in_1), .in2(c_in_2), .in3(c_in_3),
        .out1(s1_c_dly_1), .out2(s1_c_dly_2), .out3(s1_c_dly_3)
    );
    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg1_d (
        .clk(clk), .rst(rst), 
        .in1(d_in_1), .in2(d_in_2), .in3(d_in_3),
        .out1(s1_d_dly_1), .out2(s1_d_dly_2), .out3(s1_d_dly_3)
    );
    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg1_b (
        .clk(clk), .rst(rst),
        .in1(b_in_1), .in2(b_in_2), .in3(b_in_3),
        .out1(s1_b_dly_1), .out2(s1_b_dly_2), .out3(s1_b_dly_3)
    );

    // D = (D ^ A_sum) <<< 16
    wire [31:0] s1_d_rot_1, s1_d_rot_2, s1_d_rot_3;
    
    // Linear ops applied share-wise
    assign s1_d_rot_1 = rotl32((s1_d_dly_1 ^ s1_a_sum_1), 16);
    assign s1_d_rot_2 = rotl32((s1_d_dly_2 ^ s1_a_sum_2), 16);
    assign s1_d_rot_3 = rotl32((s1_d_dly_3 ^ s1_a_sum_3), 16);


    // --- Stage 2: c += d; b ^= c; b <<<= 12 ---
    wire [31:0] s2_c_sum_1, s2_c_sum_2, s2_c_sum_3;

    // C = C + D
    ksa_ti_3 #(.N_BITS(32)) adder_stg2 (
        .clk(clk), .rst(rst), .run(run_ksa),
        .rand_bits(rand_bits[63:32]),
        .a_in_1(s1_c_dly_1), .a_in_2(s1_c_dly_2), .a_in_3(s1_c_dly_3),
        .b_in_1(s1_d_rot_1), .b_in_2(s1_d_rot_2), .b_in_3(s1_d_rot_3),
        .s_out_1(s2_c_sum_1), .s_out_2(s2_c_sum_2), .s_out_3(s2_c_sum_3)
    );

    // Delay A and B
    wire [31:0] s2_a_dly_1, s2_a_dly_2, s2_a_dly_3;
    wire [31:0] s2_b_dly_1, s2_b_dly_2, s2_b_dly_3;
    wire [31:0] s2_d_dly_1, s2_d_dly_2, s2_d_dly_3; 

    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg2_a (
        .clk(clk), .rst(rst),
        .in1(s1_a_sum_1), .in2(s1_a_sum_2), .in3(s1_a_sum_3),
        .out1(s2_a_dly_1), .out2(s2_a_dly_2), .out3(s2_a_dly_3)
    );
    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg2_b (
        .clk(clk), .rst(rst),
        .in1(s1_b_dly_1), .in2(s1_b_dly_2), .in3(s1_b_dly_3),
        .out1(s2_b_dly_1), .out2(s2_b_dly_2), .out3(s2_b_dly_3)
    );
    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg2_d (
        .clk(clk), .rst(rst),
        .in1(s1_d_rot_1), .in2(s1_d_rot_2), .in3(s1_d_rot_3),
        .out1(s2_d_dly_1), .out2(s2_d_dly_2), .out3(s2_d_dly_3)
    );

    // B = (B ^ C_sum) <<< 12
    wire [31:0] s2_b_rot_1, s2_b_rot_2, s2_b_rot_3;
    
    assign s2_b_rot_1 = rotl32((s2_b_dly_1 ^ s2_c_sum_1), 12);
    assign s2_b_rot_2 = rotl32((s2_b_dly_2 ^ s2_c_sum_2), 12);
    assign s2_b_rot_3 = rotl32((s2_b_dly_3 ^ s2_c_sum_3), 12);


    // --- Stage 3: a += b; d ^= a; d <<<= 8 ---
    wire [31:0] s3_a_sum_1, s3_a_sum_2, s3_a_sum_3;

    // A = A + B
    ksa_ti_3 #(.N_BITS(32)) adder_stg3 (
        .clk(clk), .rst(rst), .run(run_ksa),
        .rand_bits(rand_bits[95:64]),
        .a_in_1(s2_a_dly_1), .a_in_2(s2_a_dly_2), .a_in_3(s2_a_dly_3),
        .b_in_1(s2_b_rot_1), .b_in_2(s2_b_rot_2), .b_in_3(s2_b_rot_3),
        .s_out_1(s3_a_sum_1), .s_out_2(s3_a_sum_2), .s_out_3(s3_a_sum_3)
    );

    // Delay C and D
    wire [31:0] s3_c_dly_1, s3_c_dly_2, s3_c_dly_3;
    wire [31:0] s3_d_dly_1, s3_d_dly_2, s3_d_dly_3;
    wire [31:0] s3_b_dly_1, s3_b_dly_2, s3_b_dly_3;

    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg3_c (
        .clk(clk), .rst(rst),
        .in1(s2_c_sum_1), .in2(s2_c_sum_2), .in3(s2_c_sum_3),
        .out1(s3_c_dly_1), .out2(s3_c_dly_2), .out3(s3_c_dly_3)
    );
    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg3_d (
        .clk(clk), .rst(rst),
        .in1(s2_d_dly_1), .in2(s2_d_dly_2), .in3(s2_d_dly_3),
        .out1(s3_d_dly_1), .out2(s3_d_dly_2), .out3(s3_d_dly_3)
    );
    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg3_b (
        .clk(clk), .rst(rst),
        .in1(s2_b_rot_1), .in2(s2_b_rot_2), .in3(s2_b_rot_3),
        .out1(s3_b_dly_1), .out2(s3_b_dly_2), .out3(s3_b_dly_3)
    );

    // D = (D ^ A_sum) <<< 8
    wire [31:0] s3_d_rot_1, s3_d_rot_2, s3_d_rot_3;

    assign s3_d_rot_1 = rotl32((s3_d_dly_1 ^ s3_a_sum_1), 8);
    assign s3_d_rot_2 = rotl32((s3_d_dly_2 ^ s3_a_sum_2), 8);
    assign s3_d_rot_3 = rotl32((s3_d_dly_3 ^ s3_a_sum_3), 8);


    // --- Stage 4: c += d; b ^= c; b <<<= 7 ---
    wire [31:0] s4_c_sum_1, s4_c_sum_2, s4_c_sum_3;

    // C = C + D
    ksa_ti_3 #(.N_BITS(32)) adder_stg4 (
        .clk(clk), .rst(rst), .run(run_ksa),
        .rand_bits(rand_bits[127:96]),
        .a_in_1(s3_c_dly_1), .a_in_2(s3_c_dly_2), .a_in_3(s3_c_dly_3),
        .b_in_1(s3_d_rot_1), .b_in_2(s3_d_rot_2), .b_in_3(s3_d_rot_3),
        .s_out_1(s4_c_sum_1), .s_out_2(s4_c_sum_2), .s_out_3(s4_c_sum_3)
    );

    // Delay A and B
    wire [31:0] s4_a_dly_1, s4_a_dly_2, s4_a_dly_3;
    wire [31:0] s4_b_dly_1, s4_b_dly_2, s4_b_dly_3;
    wire [31:0] s4_d_dly_1, s4_d_dly_2, s4_d_dly_3;

    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg4_a (
        .clk(clk), .rst(rst),
        .in1(s3_a_sum_1), .in2(s3_a_sum_2), .in3(s3_a_sum_3),
        .out1(s4_a_dly_1), .out2(s4_a_dly_2), .out3(s4_a_dly_3)
    );
    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg4_b (
        .clk(clk), .rst(rst),
        .in1(s3_b_dly_1), .in2(s3_b_dly_2), .in3(s3_b_dly_3),
        .out1(s4_b_dly_1), .out2(s4_b_dly_2), .out3(s4_b_dly_3)
    );
    delay_line_3share #(.WIDTH(32), .DEPTH(ADDER_LATENCY)) dly_stg4_d (
        .clk(clk), .rst(rst),
        .in1(s3_d_rot_1), .in2(s3_d_rot_2), .in3(s3_d_rot_3),
        .out1(s4_d_dly_1), .out2(s4_d_dly_2), .out3(s4_d_dly_3)
    );

    // B = (B ^ C_sum) <<< 7
    wire [31:0] s4_b_rot_1, s4_b_rot_2, s4_b_rot_3;

    assign s4_b_rot_1 = rotl32((s4_b_dly_1 ^ s4_c_sum_1), 7);
    assign s4_b_rot_2 = rotl32((s4_b_dly_2 ^ s4_c_sum_2), 7);
    assign s4_b_rot_3 = rotl32((s4_b_dly_3 ^ s4_c_sum_3), 7);

    // --- OUTPUT ---
    
    assign a_out_1 = s4_a_dly_1; assign a_out_2 = s4_a_dly_2; assign a_out_3 = s4_a_dly_3;
    assign b_out_1 = s4_b_rot_1; assign b_out_2 = s4_b_rot_2; assign b_out_3 = s4_b_rot_3;
    assign c_out_1 = s4_c_sum_1; assign c_out_2 = s4_c_sum_2; assign c_out_3 = s4_c_sum_3;
    assign d_out_1 = s4_d_dly_1; assign d_out_2 = s4_d_dly_2; assign d_out_3 = s4_d_dly_3;


    // --- LOCAL FUNCTIONS AND SUBMODULES ---
    
    // 32-bit left rotate
    function [31:0] rotl32;
        input [31:0] val;
        input [5:0]  amt;
        begin
            rotl32 = (val << amt) | (val >> (32 - amt));
        end
    endfunction

endmodule


// GENERIC 3-SHARE DELAY LINE (SHIFT REGISTER)
module delay_line_3share #(
    parameter WIDTH = 32,
    parameter DEPTH = 6
)(
    input  wire clk,
    input  wire rst,
    input  wire [WIDTH-1:0] in1, in2, in3,
    output wire [WIDTH-1:0] out1, out2, out3
);
    reg [WIDTH-1:0] pipe1 [0:DEPTH-1];
    reg [WIDTH-1:0] pipe2 [0:DEPTH-1];
    reg [WIDTH-1:0] pipe3 [0:DEPTH-1];
    
    integer i;

    always @(posedge clk) begin
        if (rst) begin
            for(i=0; i<DEPTH; i=i+1) begin
                pipe1[i] <= 0; pipe2[i] <= 0; pipe3[i] <= 0;
            end
        end else begin 
            pipe1[0] <= in1;
            pipe2[0] <= in2;
            pipe3[0] <= in3;
            for(i=1; i<DEPTH; i=i+1) begin
                pipe1[i] <= pipe1[i-1];
                pipe2[i] <= pipe2[i-1];
                pipe3[i] <= pipe3[i-1];
            end
        end
    end

    assign out1 = pipe1[DEPTH-1];
    assign out2 = pipe2[DEPTH-1];
    assign out3 = pipe3[DEPTH-1];

endmodule