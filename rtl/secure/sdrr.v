`default_nettype none
// Boolean-to-Arithmetic SDRR universal gadget with fresh randomness
// and conditional modular reduction.

module b2a_sdrr_universal_gadget #(
    parameter WIDTH = 130,
    parameter MOD_P_OP = 1 
)(
    input  wire             clk,
    input  wire             rst,
    input  wire             sel,            
    input  wire [WIDTH-1:0] sh1, sh2, sh3, 
    input  wire [WIDTH-1:0] arith_mask,     
    input  wire [WIDTH-1:0] noise_1, noise_2, noise_3,
    input  wire [WIDTH-1:0] logic_and_mask, 
    input  wire [WIDTH-1:0] logic_or_mask,  
    
    output reg  [WIDTH-1:0] val_out_oscillating
);

    localparam [130:0] P = {1'b1, 130'b0} - 5;

    // --- SDRR INPUT REGISTERS ---
    (* DONT_TOUCH = "TRUE" *) reg [WIDTH-1:0] r_op_sh1, r_op_sh2, r_op_sh3, r_op_mask_arith;

    // Intermediate combinational signals
    wire [WIDTH-1:0] t_comb;
    wire [WIDTH:0]   diff_raw;
    wire [WIDTH-1:0] diff_final;

    // 1. SDRR INPUT STAGE (MUX REGISTERED)
    always @(posedge clk) begin
        if (rst) begin
            r_op_sh1 <= 0;
            r_op_sh2 <= 0;
            r_op_sh3 <= 0;
            r_op_mask_arith <= 0;
        end else begin
            r_op_mask_arith <= arith_mask;
            if (sel) begin
                // DATA phase: load real shares
                r_op_sh1 <= sh1;
                r_op_sh2 <= sh2;
                r_op_sh3 <= sh3;
            end else begin
                // NOISE phase: load random shares
                r_op_sh1 <= noise_1;
                r_op_sh2 <= noise_2;
                r_op_sh3 <= noise_3;
            end
        end
    end

    // 2. Protected Boolean logic
    assign t_comb = ((r_op_sh1 ^ r_op_sh2 ^ r_op_sh3) & logic_and_mask) | logic_or_mask;

    // 3. Arithmetic conversion
    assign diff_raw = {1'b0, t_comb} - {1'b0, r_op_mask_arith};

    // 4. Conditional modular reduction
    assign diff_final = (MOD_P_OP && diff_raw[WIDTH]) ? 
                        (diff_raw[WIDTH-1:0] + P[WIDTH-1:0]) : 
                        diff_raw[WIDTH-1:0];

    // 5. Sequential output (pipeline stage)
    always @(posedge clk) begin
        if (rst) begin
            val_out_oscillating  <= 0;
        end else begin
            val_out_oscillating  <= diff_final; 
        end
    end

endmodule