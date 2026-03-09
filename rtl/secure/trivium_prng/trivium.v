// Fully unrolled Trivium stream cipher (ISO/IEC 29192-3) for CSPRNG.
module trivium #(
                parameter OUTPUT_BITS = 1024
                )
                (
                input  wire clk,                                // Clock Signal
                input  wire rst,                                // Synchronous Reset
                input  wire en,                                 // Enable Signal (1 = Run, 0 = Pause)
                input  wire [79:0] key,                         // 80-bit KEY
                input  wire [79:0] iv,                          // 80-bit IV
                output wire [OUTPUT_BITS-1:0] stream_out,       // Stream Output
                output wire valid                               // High when Warm-Up is complete
                );

    // --- Constants & Parameters ---
    // Trivium requires 1152 steps of warm-up.
    // We calculate how many clock cycles this takes based on the unroll factor.
    // Formula: ceil(1152 / OUTPUT_BITS)
    localparam WARMUP_CYCLES = (1152 + OUTPUT_BITS - 1) / OUTPUT_BITS;
    localparam CNT_WIDTH = $clog2(WARMUP_CYCLES + 1);

    // --- Internal Signals ---
    // The flip-flop state (Current Cycle)
    reg [287:0] state_reg;

    // Warm-up Counter
    reg [CNT_WIDTH-1:0] warmup_counter;

    // The unrolled combinatorial states (Future Steps)
    // Index 0 connects to state_reg, 1..OUTPUT_BITS are pure logic
    wire [287:0] state_wire [0:OUTPUT_BITS] /* verilator split_var */;
    
    // Intermediate XOR results for each step
    wire [OUTPUT_BITS-1:0] t1;
    wire [OUTPUT_BITS-1:0] t2;
    wire [OUTPUT_BITS-1:0] t3;

    // --- Connect Register to Wire Array ---
    assign state_wire[0] = state_reg;

    // --- Sequential Logic (Flip-Flops) ---
    always @(posedge clk) begin
        if (rst) begin
            // Initialization per Trivium Spec
            // Maps to {C(111), B(84), A(93)}
            state_reg <= {
                          3'b111, 108'd0,        // C (111 bits)
                          4'd0,   iv,            // B (84 bits)
                          13'd0,  key            // A (93 bits)
                          };

            warmup_counter <= {CNT_WIDTH{1'b0}};
        end 
        else if (en) begin
            // Update state with the final result of the unrolled chain
            state_reg <= state_wire[OUTPUT_BITS];

            if (warmup_counter < WARMUP_CYCLES) begin
                warmup_counter <= warmup_counter + 1'b1;
            end
        end
    end

    // --- Combinatorial Logic (The Unrolling) ---
    genvar i;
    generate
        for (i = 1; i <= OUTPUT_BITS; i = i + 1) begin : unroll_loop
            // Note: i-1 refers to the previous state in the chain
            
            // 1. Calculate T values based on PREVIOUS state (i-1)
            // t1 -> Feedback from B (161, 176)
            // t2 -> Feedback from A (65, 92)
            // t3 -> Feedback from C (242, 287)
            
            assign t1[i-1] = state_wire[i-1][161] ^ state_wire[i-1][176];
            assign t2[i-1] = state_wire[i-1][65]  ^ state_wire[i-1][92];
            assign t3[i-1] = state_wire[i-1][242] ^ state_wire[i-1][287];

            // 2. Compute the NEXT state (i)
            // Structure: { C_shifted, new_C_bit, B_shifted, new_B_bit, A_shifted, new_A_bit }
            
            assign state_wire[i] = {
                                    // Shift C (High part), inject t1 logic
                                    state_wire[i-1][286:177], 
                                    (t1[i-1] ^ (state_wire[i-1][174] & state_wire[i-1][175]) ^ state_wire[i-1][263]),

                                    // Shift B (Mid part), inject t2 logic
                                    state_wire[i-1][175:93],  
                                    (t2[i-1] ^ (state_wire[i-1][90]  & state_wire[i-1][91])  ^ state_wire[i-1][170]),

                                    // Shift A (Low part), inject t3 logic
                                    state_wire[i-1][91:0],    
                                    (t3[i-1] ^ (state_wire[i-1][285] & state_wire[i-1][286]) ^ state_wire[i-1][68])
                                    };
        end
    endgenerate

    // --- Output Assignments ---
    generate
        for (i = 1; i <= OUTPUT_BITS; i = i + 1) begin : output_loop
             // If i=1 (loop start), index is OUTPUT_BITS-1 (max index)
             assign stream_out[i-1] = t1[OUTPUT_BITS-i] ^ t2[OUTPUT_BITS-i] ^ t3[OUTPUT_BITS-i];
        end
    endgenerate

    assign valid = (warmup_counter == WARMUP_CYCLES);

endmodule
