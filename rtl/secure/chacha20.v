`default_nettype none
// Masked ChaCha20 core (3-share TI) with distributed RAM for init state
// storage, pipelined ARX stages with KSA, and randomness harvesting.

module chacha20_core_msk #(
    parameter integer PIPELINE_STAGES = 2,
    parameter integer CIPHER_ROUNDS   = 20
)(
    input  wire          clk,
    input  wire          rst,
    input  wire [31:0]   init_ctr,
    input  wire          next_ctr,
    input  wire          cc_init,
    input  wire          cc_next,
    input  wire [255:0]  key,
    input  wire [95:0]   nonce,
    input  wire [519:0]  prng_input, 
    output reg  [511:0]  keystream_sh1,
    output reg  [511:0]  keystream_sh2,
    output reg  [511:0]  keystream_sh3,
    output reg  [255:0]  poly_key_sh1,
    output reg  [255:0]  poly_key_sh2,
    output reg  [255:0]  poly_key_sh3,
    output reg           valid_out,
    output reg           ready
);

    // =========================================================================
    // 1. CONSTANTS
    // =========================================================================
    localparam [31:0] C0 = 32'h61707865;
    localparam [31:0] C1 = 32'h3320646e;
    localparam [31:0] C2 = 32'h79622d32;
    localparam [31:0] C3 = 32'h6b206574;

    // FSM States
    localparam [3:0] IDLE         = 4'd0;
    localparam [3:0] HARVEST      = 4'd1;
    localparam [3:0] LOAD_STAGE   = 4'd2;
    localparam [3:0] PRIME_EXEC   = 4'd3;
    localparam [3:0] PRIME_SHIFT  = 4'd4;
    localparam [3:0] RUN_EXEC     = 4'd5;
    localparam [3:0] RUN_SHIFT    = 4'd6;
    localparam [3:0] SECURE_SUM   = 4'd7; 
    localparam [3:0] FINALIZE_1   = 4'd8; 
    localparam [3:0] FINALIZE_2   = 4'd9; 
    localparam [3:0] FINALIZE_3   = 4'd10; 
    localparam [3:0] OUTPUT_HOLD  = 4'd11;

    // =========================================================================
    // 2. OPTIMIZED STORAGE (Distributed RAM vs Pipeline Regs)
    // =========================================================================
    
    // Working State Pipeline (Must physically shift)
    (* DONT_TOUCH = "TRUE" *) reg [31:0] state_regs [0:PIPELINE_STAGES-1][0:15][0:2];
    
    // OPTIMIZATION: Initial State Storage (Distributed RAM)
    // Instead of shifting 1536 bits per stage, we store them in LUTRAM and address them.
    // Size: Pipeline Depth * 16 words * 3 shares
    (* ram_style = "distributed" *) reg [31:0] init_state_ram [0:(PIPELINE_STAGES*16)-1][0:2];
    
    // We pass a 'Slot ID' through the pipeline instead of the whole data
    reg [$clog2(PIPELINE_STAGES)-1:0] slot_id_pipeline [0:PIPELINE_STAGES-1];
    reg [$clog2(PIPELINE_STAGES)-1:0] next_slot_id_pipeline [0:PIPELINE_STAGES-1];
    
    // Tracking current loading slot
    reg [$clog2(PIPELINE_STAGES)-1:0] load_slot_ptr;

    // Standard control regs
    reg [4:0]  rounds_done      [0:PIPELINE_STAGES-1];        
    reg        slot_valid       [0:PIPELINE_STAGES-1];        

    reg [3:0]  state;
    reg [31:0] loading_ctr;
    reg [1:0]  harvest_cnt;      
    reg [31:0] mask_a [0:15];
    reg [31:0] mask_b [0:15];
    
    reg [4:0]  items_in_flight; 
    reg [4:0]  items_loaded;    
    reg        poly_key_generated;
    
    // ARX Signals
    wire [31:0] arx_in_flat  [0:PIPELINE_STAGES-1][0:15][0:2];
    wire [31:0] arx_out_flat [0:PIPELINE_STAGES-1][0:15][0:2];
    wire [PIPELINE_STAGES-1:0] arx_done; 
    reg  [PIPELINE_STAGES-1:0] arx_enable; 

    // Next State Logic Vars
    reg [31:0] next_state_regs  [0:PIPELINE_STAGES-1][0:15][0:2];   
    reg [4:0]  next_rounds_done [0:PIPELINE_STAGES-1];
    reg        next_slot_valid  [0:PIPELINE_STAGES-1];

    integer k, s, idx_s, idx_w, prev_s, mx; 
    wire run_ksa_arx;
    
    assign run_ksa_arx = (state != IDLE && state != SECURE_SUM && state != FINALIZE_1 && state != FINALIZE_2 && state != FINALIZE_3 && state != OUTPUT_HOLD);

    // Helpers
    // To check if block is counter 0 (for Poly key), we need to read from the RAM
    reg [31:0] retrieved_counter_share0, retrieved_counter_share1, retrieved_counter_share2;
    wire [31:0] current_counter_val;
    wire        is_poly_key_block;
    reg [511:0] func_out_comb;
    reg [511:0] current_mask_comb;
    
    // Calculate current counter from RAM shares
    assign current_counter_val = retrieved_counter_share0 ^ retrieved_counter_share1 ^ retrieved_counter_share2;
    assign is_poly_key_block = (current_counter_val == 32'd0);
    
    // =========================================================================
    // 3. INTEGRATION KOGGE-STONE ADDER (KSA)
    // =========================================================================
    (* DONT_TOUCH = "TRUE" *) reg [31:0] sum_storage [0:15][0:2];
    reg [4:0]  ksa_counter;        
    reg        ksa_run;            
    
    // Mux inputs/outputs
    reg  [31:0] ksa_in_a1 [0:3], ksa_in_a2 [0:3], ksa_in_a3 [0:3];
    reg  [31:0] ksa_in_b1 [0:3], ksa_in_b2 [0:3], ksa_in_b3 [0:3];
    wire [31:0] ksa_out_s1 [0:3], ksa_out_s2 [0:3], ksa_out_s3 [0:3];
    
    localparam KSA_LATENCY = 7; 

    genvar i;
    generate
        for (i = 0; i < 4; i = i + 1) begin : gen_ksa_4
            (* KEEP_HIERARCHY = "YES" *) ksa_ti_3 #( .N_BITS(32) ) u_ksa_core (
                .clk(clk), .rst(rst),
                .run(ksa_run),
                .rand_bits(prng_input[(i*32) +: 32]), 
                .a_in_1(ksa_in_a1[i]), .a_in_2(ksa_in_a2[i]), .a_in_3(ksa_in_a3[i]),
                .b_in_1(ksa_in_b1[i]), .b_in_2(ksa_in_b2[i]), .b_in_3(ksa_in_b3[i]),
                .s_out_1(ksa_out_s1[i]), .s_out_2(ksa_out_s2[i]), .s_out_3(ksa_out_s3[i])
            );
        end
    endgenerate

    // =========================================================================
    // 4. PIPELINE ROTATION LOGIC
    // =========================================================================
    always @* begin
        for (idx_s = 0; idx_s < PIPELINE_STAGES; idx_s = idx_s + 1) begin
            next_slot_valid[idx_s]  = 0; 
            next_rounds_done[idx_s] = 0;
            next_slot_id_pipeline[idx_s] = 0;
            
            for (idx_w = 0; idx_w < 16; idx_w = idx_w + 1) begin
                next_state_regs[idx_s][idx_w][0] = 32'b0; 
                next_state_regs[idx_s][idx_w][1] = 32'b0; 
                next_state_regs[idx_s][idx_w][2] = 32'b0;
            end
        end

        for (idx_s = 0; idx_s < PIPELINE_STAGES; idx_s = idx_s + 1) begin
            prev_s = (idx_s == 0) ? (PIPELINE_STAGES - 1) : (idx_s - 1);
            
            for (idx_w = 0; idx_w < 16; idx_w = idx_w + 1) begin
                next_state_regs[idx_s][idx_w][0] = arx_out_flat[prev_s][idx_w][0];
                next_state_regs[idx_s][idx_w][1] = arx_out_flat[prev_s][idx_w][1];
                next_state_regs[idx_s][idx_w][2] = arx_out_flat[prev_s][idx_w][2];
            end
            
            next_rounds_done[idx_s] = rounds_done[prev_s] + 1;
            next_slot_valid[idx_s]  = slot_valid[prev_s];
            next_slot_id_pipeline[idx_s] = slot_id_pipeline[prev_s];
        end
    end

    // =========================================================================
    // 5. MAPPING & ARX GENERATION
    // =========================================================================
    genvar g, w;
    generate
        for (g = 0; g < PIPELINE_STAGES; g = g + 1) begin : map_in
            for (w = 0; w < 16; w = w + 1) begin : map_w
                assign arx_in_flat[g][w][0] = state_regs[g][w][0];
                assign arx_in_flat[g][w][1] = state_regs[g][w][1];
                assign arx_in_flat[g][w][2] = state_regs[g][w][2];
            end
        end
    endgenerate

    generate
        for (g = 0; g < PIPELINE_STAGES; g = g + 1) begin : arx_gen
            (* KEEP_HIERARCHY = "YES" *) chacha20_arx_single_ti3 arx_inst (
                .clk(clk), .rst(rst),
                .enable(arx_enable[g]),
                .run_ksa(run_ksa_arx),
                .mode(g % 2), 
                .rand_bits(prng_input[255:0]),
                // Inputs
                .m0_1(arx_in_flat[g][0][0]), .m0_2(arx_in_flat[g][0][1]), .m0_3(arx_in_flat[g][0][2]),
                .m1_1(arx_in_flat[g][1][0]), .m1_2(arx_in_flat[g][1][1]), .m1_3(arx_in_flat[g][1][2]),
                .m2_1(arx_in_flat[g][2][0]), .m2_2(arx_in_flat[g][2][1]), .m2_3(arx_in_flat[g][2][2]),
                .m3_1(arx_in_flat[g][3][0]), .m3_2(arx_in_flat[g][3][1]), .m3_3(arx_in_flat[g][3][2]),
                .m4_1(arx_in_flat[g][4][0]), .m4_2(arx_in_flat[g][4][1]), .m4_3(arx_in_flat[g][4][2]),
                .m5_1(arx_in_flat[g][5][0]), .m5_2(arx_in_flat[g][5][1]), .m5_3(arx_in_flat[g][5][2]),
                .m6_1(arx_in_flat[g][6][0]), .m6_2(arx_in_flat[g][6][1]), .m6_3(arx_in_flat[g][6][2]),
                .m7_1(arx_in_flat[g][7][0]), .m7_2(arx_in_flat[g][7][1]), .m7_3(arx_in_flat[g][7][2]),
                .m8_1(arx_in_flat[g][8][0]), .m8_2(arx_in_flat[g][8][1]), .m8_3(arx_in_flat[g][8][2]),
                .m9_1(arx_in_flat[g][9][0]), .m9_2(arx_in_flat[g][9][1]), .m9_3(arx_in_flat[g][9][2]),
                .m10_1(arx_in_flat[g][10][0]), .m10_2(arx_in_flat[g][10][1]), .m10_3(arx_in_flat[g][10][2]),
                .m11_1(arx_in_flat[g][11][0]), .m11_2(arx_in_flat[g][11][1]), .m11_3(arx_in_flat[g][11][2]),
                .m12_1(arx_in_flat[g][12][0]), .m12_2(arx_in_flat[g][12][1]), .m12_3(arx_in_flat[g][12][2]),
                .m13_1(arx_in_flat[g][13][0]), .m13_2(arx_in_flat[g][13][1]), .m13_3(arx_in_flat[g][13][2]), 
                .m14_1(arx_in_flat[g][14][0]), .m14_2(arx_in_flat[g][14][1]), .m14_3(arx_in_flat[g][14][2]),
                .m15_1(arx_in_flat[g][15][0]), .m15_2(arx_in_flat[g][15][1]), .m15_3(arx_in_flat[g][15][2]), 

                // Outputs
                .m0x_1(arx_out_flat[g][0][0]), .m0x_2(arx_out_flat[g][0][1]), .m0x_3(arx_out_flat[g][0][2]),
                .m1x_1(arx_out_flat[g][1][0]), .m1x_2(arx_out_flat[g][1][1]), .m1x_3(arx_out_flat[g][1][2]),
                .m2x_1(arx_out_flat[g][2][0]), .m2x_2(arx_out_flat[g][2][1]), .m2x_3(arx_out_flat[g][2][2]),
                .m3x_1(arx_out_flat[g][3][0]), .m3x_2(arx_out_flat[g][3][1]), .m3x_3(arx_out_flat[g][3][2]),
                .m4x_1(arx_out_flat[g][4][0]), .m4x_2(arx_out_flat[g][4][1]), .m4x_3(arx_out_flat[g][4][2]),
                .m5x_1(arx_out_flat[g][5][0]), .m5x_2(arx_out_flat[g][5][1]), .m5x_3(arx_out_flat[g][5][2]),
                .m6x_1(arx_out_flat[g][6][0]), .m6x_2(arx_out_flat[g][6][1]), .m6x_3(arx_out_flat[g][6][2]),
                .m7x_1(arx_out_flat[g][7][0]), .m7x_2(arx_out_flat[g][7][1]), .m7x_3(arx_out_flat[g][7][2]),
                .m8x_1(arx_out_flat[g][8][0]), .m8x_2(arx_out_flat[g][8][1]), .m8x_3(arx_out_flat[g][8][2]),
                .m9x_1(arx_out_flat[g][9][0]), .m9x_2(arx_out_flat[g][9][1]), .m9x_3(arx_out_flat[g][9][2]),
                .m10x_1(arx_out_flat[g][10][0]), .m10x_2(arx_out_flat[g][10][1]), .m10x_3(arx_out_flat[g][10][2]),
                .m11x_1(arx_out_flat[g][11][0]), .m11x_2(arx_out_flat[g][11][1]), .m11x_3(arx_out_flat[g][11][2]),
                .m12x_1(arx_out_flat[g][12][0]), .m12x_2(arx_out_flat[g][12][1]), .m12x_3(arx_out_flat[g][12][2]),
                .m13x_1(arx_out_flat[g][13][0]), .m13x_2(arx_out_flat[g][13][1]), .m13x_3(arx_out_flat[g][13][2]),
                .m14x_1(arx_out_flat[g][14][0]), .m14x_2(arx_out_flat[g][14][1]), .m14x_3(arx_out_flat[g][14][2]),
                .m15x_1(arx_out_flat[g][15][0]), .m15x_2(arx_out_flat[g][15][1]), .m15x_3(arx_out_flat[g][15][2]),
                
                .out_valid(arx_done[g])
            );
        end
    endgenerate
    
    // =========================================================================
    // 6. OUTPUT COMBINATION
    // =========================================================================  

    always @* begin
        if (state == FINALIZE_3) 
            current_mask_comb = keystream_sh3; 
        else 
            current_mask_comb = prng_input[511:0]; 

        case (state)
            FINALIZE_1: func_out_comb = calc_single_share_pack(0, current_mask_comb);
            FINALIZE_2: func_out_comb = calc_single_share_pack(1, current_mask_comb);
            FINALIZE_3: func_out_comb = calc_single_share_pack(2, current_mask_comb);
            default:    func_out_comb = prng_input[511:0];
        endcase
    end

    // =========================================================================
    // 7. MAIN CONTROLLER
    // =========================================================================    
    
    // Internal Init State temporary registers (just to hold logic before writing to RAM)
    reg [31:0] temp_init [0:15][0:2];

    always @(posedge clk) begin
        if (rst) begin
            state            <= IDLE;
            loading_ctr      <= 0;
            harvest_cnt      <= 0;
            items_in_flight  <= 0;
            items_loaded     <= 0;
            ready            <= 1;
            valid_out        <= 0;
            arx_enable       <= 0;
            
            // Pointers
            load_slot_ptr <= 0;
            
            // KSA Reset
            ksa_run <= 0;
            ksa_counter <= 0;
            
            // Output Regs Reset
            keystream_sh1 <= 0; keystream_sh2 <= 0; keystream_sh3 <= 0;
            poly_key_sh1 <= 0; poly_key_sh2 <= 0; poly_key_sh3 <= 0;
            poly_key_generated <= 0;
            
            // Reset Arrays
            for(s=0; s<PIPELINE_STAGES; s=s+1) begin
                slot_valid[s]  <= 0;
                rounds_done[s] <= 0;
                slot_id_pipeline[s] <= 0;
                for(k=0; k<16; k=k+1) begin
                    state_regs[s][k][0]<=0; state_regs[s][k][1]<=0; state_regs[s][k][2]<=0;
                end
            end
            for(k=0; k<16; k=k+1) begin
                sum_storage[k][0] <= 0; sum_storage[k][1] <= 0; sum_storage[k][2] <= 0;
            end
            
        end else begin
            arx_enable <= 0; 
            valid_out  <= 0; 
            ksa_run    <= 0; 
            
            // Pre-charge Randomization
            if (!valid_out && state != IDLE) begin
                if (state < FINALIZE_1)     keystream_sh1 <= prng_input[511:0];
                if (state < FINALIZE_2)     keystream_sh2 <= {prng_input[255:0], prng_input[511:256]};
                if (state < FINALIZE_1)     keystream_sh3 <= {~prng_input[127:0], prng_input[383:256], ~prng_input[511:384], prng_input[255:128]};

                if (!poly_key_generated) begin
                    if (state < FINALIZE_1) poly_key_sh1 <= prng_input[255:0];
                    if (state < FINALIZE_2) poly_key_sh2 <= {prng_input[127:0], prng_input[255:128]}; 
                    if (state < FINALIZE_3) poly_key_sh3 <= {~prng_input[63:0], prng_input[191:128], ~prng_input[255:192], prng_input[127:64]};
                end
            end
            
            // Fetch from Distributed RAM for KSA
            // Retrieve based on the slot_id of the block exiting the pipeline (Stage 0)
            retrieved_counter_share0 <= init_state_ram[(slot_id_pipeline[0]*16) + 12][0];
            retrieved_counter_share1 <= init_state_ram[(slot_id_pipeline[0]*16) + 12][1];
            retrieved_counter_share2 <= init_state_ram[(slot_id_pipeline[0]*16) + 12][2];

            for(mx=0; mx<4; mx=mx+1) begin
                ksa_in_a1[mx] <= state_regs[0][(ksa_counter[1:0]*4) + mx][0];
                ksa_in_a2[mx] <= state_regs[0][(ksa_counter[1:0]*4) + mx][1];
                ksa_in_a3[mx] <= state_regs[0][(ksa_counter[1:0]*4) + mx][2];
                
                // Read B from Distributed RAM based on Slot ID
                ksa_in_b1[mx] <= init_state_ram[(slot_id_pipeline[0]*16) + (ksa_counter[1:0]*4) + mx][0];
                ksa_in_b2[mx] <= init_state_ram[(slot_id_pipeline[0]*16) + (ksa_counter[1:0]*4) + mx][1];
                ksa_in_b3[mx] <= init_state_ram[(slot_id_pipeline[0]*16) + (ksa_counter[1:0]*4) + mx][2];
            end

            case (state)
                IDLE: begin
                    ready <= 1;
                    if (cc_init || cc_next || next_ctr) begin
                        if (cc_init) begin 
                            loading_ctr <= init_ctr;
                            poly_key_generated <= 0;
                        end else loading_ctr <= loading_ctr + 1;
                        
                        ready        <= 0;
                        harvest_cnt  <= 0;
                        items_loaded <= 0;
                        state        <= HARVEST;
                    end
                end

                HARVEST: begin  
                    harvest_cnt <= harvest_cnt + 1;
                    case (harvest_cnt)
                        3'd0: {mask_a[15], mask_a[14], mask_a[13], mask_a[12], mask_a[11], mask_a[10], mask_a[9], mask_a[8], mask_a[7], mask_a[6], mask_a[5], mask_a[4], mask_a[3], mask_a[2], mask_a[1], mask_a[0]} <= prng_input[511:0];
                        3'd1: begin
                            {mask_b[15], mask_b[14], mask_b[13], mask_b[12], mask_b[11], mask_b[10], mask_b[9], mask_b[8], mask_b[7], mask_b[6], mask_b[5], mask_b[4], mask_b[3], mask_b[2], mask_b[1], mask_b[0]} <= prng_input[511:0];
                            state <= LOAD_STAGE;
                        end
                    endcase
                end

                LOAD_STAGE: begin    
                    // Prepare data (Combinational calculation for readability)
                    temp_init[0][0] = C0 ^ mask_a[0] ^ mask_b[0];
                    temp_init[1][0] = C1 ^ mask_a[1] ^ mask_b[1];
                    temp_init[2][0] = C2 ^ mask_a[2] ^ mask_b[2];
                    temp_init[3][0] = C3 ^ mask_a[3] ^ mask_b[3];
                    temp_init[4][0]  = {key[231:224], key[239:232], key[247:240], key[255:248]} ^ mask_a[4]  ^ mask_b[4]; 
                    temp_init[5][0]  = {key[199:192], key[207:200], key[215:208], key[223:216]} ^ mask_a[5]  ^ mask_b[5]; 
                    temp_init[6][0]  = {key[167:160], key[175:168], key[183:176], key[191:184]} ^ mask_a[6]  ^ mask_b[6]; 
                    temp_init[7][0]  = {key[135:128], key[143:136], key[151:144], key[159:152]} ^ mask_a[7]  ^ mask_b[7]; 
                    temp_init[8][0]  = {key[103:96],  key[111:104], key[119:112], key[127:120]} ^ mask_a[8]  ^ mask_b[8]; 
                    temp_init[9][0]  = {key[71:64],   key[79:72],   key[87:80],   key[95:88]}   ^ mask_a[9]  ^ mask_b[9]; 
                    temp_init[10][0] = {key[39:32],   key[47:40],   key[55:48],   key[63:56]}   ^ mask_a[10] ^ mask_b[10];
                    temp_init[11][0] = {key[7:0],     key[15:8],    key[23:16],   key[31:24]}   ^ mask_a[11] ^ mask_b[11];
                    temp_init[12][0] = loading_ctr ^ mask_a[12] ^ mask_b[12];                                                                                             
                    temp_init[13][0] = {nonce[71:64], nonce[79:72], nonce[87:80], nonce[95:88]} ^ mask_a[13] ^ mask_b[13];
                    temp_init[14][0] = {nonce[39:32], nonce[47:40], nonce[55:48], nonce[63:56]} ^ mask_a[14] ^ mask_b[14];
                    temp_init[15][0] = {nonce[7:0],   nonce[15:8],  nonce[23:16], nonce[31:24]} ^ mask_a[15] ^ mask_b[15];

                    for(k=0; k<16; k=k+1) begin
                        temp_init[k][1] = mask_a[k]; 
                        temp_init[k][2] = mask_b[k]; 
                        
                        // Load Working State (Registers)
                        state_regs[0][k][0] <= temp_init[k][0];
                        state_regs[0][k][1] <= temp_init[k][1];
                        state_regs[0][k][2] <= temp_init[k][2];
                        
                        // Load Initial State (RAM - Indexed by load_slot_ptr)
                        init_state_ram[(load_slot_ptr*16) + k][0] <= temp_init[k][0];
                        init_state_ram[(load_slot_ptr*16) + k][1] <= temp_init[k][1];
                        init_state_ram[(load_slot_ptr*16) + k][2] <= temp_init[k][2];
                    end
                    
                    slot_valid[0]       <= 1;
                    rounds_done[0]      <= 0;
                    slot_id_pipeline[0] <= load_slot_ptr; // Assign ID
                    
                    items_in_flight <= items_in_flight + 1;
                    items_loaded    <= items_loaded + 1;
                    load_slot_ptr   <= load_slot_ptr + 1; // Increment for next block
                    
                    if (items_loaded + 1 == PIPELINE_STAGES) begin
                        state <= RUN_EXEC;
                    end else begin
                        state <= PRIME_EXEC; 
                        loading_ctr <= loading_ctr + 1;
                    end
                end

                PRIME_EXEC: begin
                    for(k=0; k<PIPELINE_STAGES; k=k+1) begin
                        if(slot_valid[k]) arx_enable[k] <= 1;
                    end
                    state <= PRIME_SHIFT;
                end

                PRIME_SHIFT: begin
                    if (|arx_done) begin
                        // Shift Pipeline
                        for (s = 0; s < PIPELINE_STAGES; s = s + 1) begin
                            for(k=0; k<16; k=k+1) begin
                                state_regs[s][k][0] <= next_state_regs[s][k][0];
                                state_regs[s][k][1] <= next_state_regs[s][k][1];
                                state_regs[s][k][2] <= next_state_regs[s][k][2];
                            end
                            rounds_done[s] <= next_rounds_done[s];
                            slot_valid[s]  <= next_slot_valid[s];
                            slot_id_pipeline[s] <= next_slot_id_pipeline[s]; // Shift ID
                        end
                        harvest_cnt <= 0;
                        state <= HARVEST;
                    end
                end

                RUN_EXEC: begin
                    for(k=0; k<PIPELINE_STAGES; k=k+1) begin
                        if(slot_valid[k]) arx_enable[k] <= 1;
                    end
                    state <= RUN_SHIFT;
                end

                RUN_SHIFT: begin
                    if (|arx_done) begin
                        if (slot_valid[0] && rounds_done[0] == CIPHER_ROUNDS) begin                                      
                            ksa_counter <= 0;
                            state <= SECURE_SUM;
                        end 
                        else begin
                            // Shift Pipeline
                            for (s = 0; s < PIPELINE_STAGES; s = s + 1) begin
                                for(k=0; k<16; k=k+1) begin
                                    state_regs[s][k][0] <= next_state_regs[s][k][0];
                                    state_regs[s][k][1] <= next_state_regs[s][k][1];
                                    state_regs[s][k][2] <= next_state_regs[s][k][2];
                                end
                                rounds_done[s] <= next_rounds_done[s];
                                slot_valid[s]  <= next_slot_valid[s];
                                slot_id_pipeline[s] <= next_slot_id_pipeline[s]; // Shift ID
                            end
                            state <= RUN_EXEC;
                        end
                    end
                end

                SECURE_SUM: begin
                    // KSA Logic
                    ksa_run <= 1; 
                    ksa_counter <= ksa_counter + 1;
                    
                    if (ksa_counter >= KSA_LATENCY && ksa_counter < (KSA_LATENCY + 4)) begin
                        for(mx=0; mx<4; mx=mx+1) begin
                            sum_storage[((ksa_counter - KSA_LATENCY)*4) + mx][0] <= ksa_out_s1[mx];
                            sum_storage[((ksa_counter - KSA_LATENCY)*4) + mx][1] <= ksa_out_s2[mx];
                            sum_storage[((ksa_counter - KSA_LATENCY)*4) + mx][2] <= ksa_out_s3[mx];
                        end
                    end

                    if (ksa_counter == (KSA_LATENCY + 3))   state <= FINALIZE_1;
                end
                
                FINALIZE_1: begin
                    if (is_poly_key_block) poly_key_sh1 <= func_out_comb[511 : 256]; 
                    else                   keystream_sh1 <= func_out_comb;
                    keystream_sh3 <= prng_input[511:0]; 
                    
                    state <= FINALIZE_2;
                end

                FINALIZE_2: begin
                    if (is_poly_key_block) poly_key_sh2 <= func_out_comb[511 : 256];
                    else                   keystream_sh2 <= func_out_comb;
                    
                    state <= FINALIZE_3;
                end

                FINALIZE_3: begin
                    
                    if (is_poly_key_block) begin
                        poly_key_sh3 <= func_out_comb[511 : 256];
                        poly_key_generated <= 1; 
                    end else begin
                        keystream_sh3 <= func_out_comb;
                    end
                    
                    valid_out <= 1;
                    items_in_flight <= items_in_flight - 1;
                    
                    // Rotate pipeline (shift stage 0 out)
                    for(k=0; k<16; k=k+1) begin
                        state_regs[0][k][0] <= next_state_regs[0][k][0]; 
                        state_regs[0][k][1] <= next_state_regs[0][k][1]; 
                        state_regs[0][k][2] <= next_state_regs[0][k][2];                                              
                    end
                    rounds_done[0] <= next_rounds_done[0]; 
                    slot_valid[0]  <= next_slot_valid[0];
                    slot_id_pipeline[0] <= next_slot_id_pipeline[0];
                    
                    slot_valid[PIPELINE_STAGES-1] <= 0;    
                    
                    state <= OUTPUT_HOLD;       
                end
                
                OUTPUT_HOLD: begin
                    valid_out <= 1;
                    if (next_ctr && items_in_flight != 0) begin
                        valid_out <= 0;
                        keystream_sh1 <= prng_input[511:0];
                        keystream_sh2 <= {prng_input[255:0], prng_input[511:256]};
                        keystream_sh3 <= {~prng_input[127:0], prng_input[383:256], ~prng_input[511:384], prng_input[255:128]};
                        state <= RUN_EXEC;
                    end else if (items_in_flight == 0) begin
                        state <= IDLE;       
                    end
                end
            endcase
        end
    end
    
    function automatic [511:0] calc_single_share_pack; 
        input integer target_share_idx; 
        input [511:0] entropy_mask_in; 
        
        integer kb, bb;
        reg [31:0] t_sum_current, word_processed, mask_current;
        integer bit_pos;
    
        begin
            calc_single_share_pack = 0;
            for (kb = 0; kb < 16; kb = kb + 1) begin
                t_sum_current = sum_storage[kb][target_share_idx];
                mask_current = entropy_mask_in[(kb * 32) +: 32]; 
                
                if (target_share_idx == 1) word_processed = t_sum_current; 
                else                        word_processed = t_sum_current ^ mask_current;
                
                for (bb = 0; bb < 4; bb = bb + 1) begin
                    bit_pos = ((15 - kb) * 32) + ((3 - bb) * 8);                     
                    calc_single_share_pack[bit_pos +: 8] = word_processed[(bb*8) +: 8]; 
                end
            end
        end
    endfunction
    
endmodule


module chacha20_arx_single_ti3 (
    input  wire          clk,
    input  wire          rst,
    input  wire          enable,       // Pulse high to start
    input  wire          run_ksa,      // Manage seq operation on KSA modules
    input  wire          mode,         // 0 = Column Round, 1 = Diagonal Round
    input  wire [255:0]  rand_bits,    // Randomness for masking
    
    // Flattened Inputs (16 words * 3 shares)
    input  wire [31:0]  m0_1, m0_2, m0_3, m1_1, m1_2, m1_3, m2_1, m2_2, m2_3, m3_1, m3_2, m3_3,
    input  wire [31:0]  m4_1, m4_2, m4_3, m5_1, m5_2, m5_3, m6_1, m6_2, m6_3, m7_1, m7_2, m7_3,
    input  wire [31:0]  m8_1, m8_2, m8_3, m9_1, m9_2, m9_3, m10_1, m10_2, m10_3, m11_1, m11_2, m11_3,
    input  wire [31:0]  m12_1, m12_2, m12_3, m13_1, m13_2, m13_3, m14_1, m14_2, m14_3, m15_1, m15_2, m15_3,
    
    // Flattened Outputs (16 words * 3 shares)
    output wire [31:0]  m0x_1, m0x_2, m0x_3, m1x_1, m1x_2, m1x_3, m2x_1, m2x_2, m2x_3, m3x_1, m3x_2, m3x_3,
    output wire [31:0]  m4x_1, m4x_2, m4x_3, m5x_1, m5x_2, m5x_3, m6x_1, m6x_2, m6x_3, m7x_1, m7x_2, m7x_3,
    output wire [31:0]  m8x_1, m8x_2, m8x_3, m9x_1, m9x_2, m9x_3, m10x_1, m10x_2, m10x_3, m11x_1, m11x_2, m11x_3,
    output wire [31:0]  m12x_1, m12x_2, m12x_3, m13x_1, m13x_2, m13x_3, m14x_1, m14x_2, m14x_3, m15x_1, m15x_2, m15x_3,
    
    output reg          out_valid
);

    // =========================================================================
    // 1. INPUT PACKING (Flattened -> Array)
    // =========================================================================
    wire [31:0] in_m [0:15][0:2];
    
    assign in_m[0][0]=m0_1;   assign in_m[0][1]=m0_2;   assign in_m[0][2]=m0_3;
    assign in_m[1][0]=m1_1;   assign in_m[1][1]=m1_2;   assign in_m[1][2]=m1_3;
    assign in_m[2][0]=m2_1;   assign in_m[2][1]=m2_2;   assign in_m[2][2]=m2_3;
    assign in_m[3][0]=m3_1;   assign in_m[3][1]=m3_2;   assign in_m[3][2]=m3_3;
    assign in_m[4][0]=m4_1;   assign in_m[4][1]=m4_2;   assign in_m[4][2]=m4_3;
    assign in_m[5][0]=m5_1;   assign in_m[5][1]=m5_2;   assign in_m[5][2]=m5_3;
    assign in_m[6][0]=m6_1;   assign in_m[6][1]=m6_2;   assign in_m[6][2]=m6_3;
    assign in_m[7][0]=m7_1;   assign in_m[7][1]=m7_2;   assign in_m[7][2]=m7_3;
    assign in_m[8][0]=m8_1;   assign in_m[8][1]=m8_2;   assign in_m[8][2]=m8_3;
    assign in_m[9][0]=m9_1;   assign in_m[9][1]=m9_2;   assign in_m[9][2]=m9_3;
    assign in_m[10][0]=m10_1; assign in_m[10][1]=m10_2; assign in_m[10][2]=m10_3;
    assign in_m[11][0]=m11_1; assign in_m[11][1]=m11_2; assign in_m[11][2]=m11_3;
    assign in_m[12][0]=m12_1; assign in_m[12][1]=m12_2; assign in_m[12][2]=m12_3;
    assign in_m[13][0]=m13_1; assign in_m[13][1]=m13_2; assign in_m[13][2]=m13_3;
    assign in_m[14][0]=m14_1; assign in_m[14][1]=m14_2; assign in_m[14][2]=m14_3;
    assign in_m[15][0]=m15_1; assign in_m[15][1]=m15_2; assign in_m[15][2]=m15_3;

    // =========================================================================
    // 2. CONTROL & PIPELINE SYNC
    // =========================================================================
    localparam QR_LATENCY = 24; 
    
    reg [2:0] feed_cnt;       
    reg       feeding;        
    reg       mode_latched;   

    reg [2:0] idx_dly [0:QR_LATENCY-1]; 
    reg       val_dly [0:QR_LATENCY-1];
    integer i;

    always @(posedge clk) begin
        if (rst) begin
            feed_cnt <= 0;
            feeding  <= 0;
            out_valid <= 0;
            mode_latched <= 0;
            for(i=0; i<QR_LATENCY; i=i+1) begin
                idx_dly[i] <= 0;
                val_dly[i] <= 0;
            end
        end else begin 
            if (enable) begin
                feeding <= 1;
                feed_cnt <= 0;
                mode_latched <= mode; 
            end

            if (feeding) begin
                if (feed_cnt == 3) begin
                    feeding <= 0;
                end else begin
                    feed_cnt <= feed_cnt + 1;
                end
            end

            idx_dly[0] <= feed_cnt;
            val_dly[0] <= feeding;

            for(i=1; i<QR_LATENCY; i=i+1) begin
                idx_dly[i] <= idx_dly[i-1];
                val_dly[i] <= val_dly[i-1];
            end

            if (val_dly[QR_LATENCY-1] && idx_dly[QR_LATENCY-1] == 3) begin
                out_valid <= 1;
            end else begin
                out_valid <= 0;
            end
        end
    end

    wire [1:0] curr_wr_idx = idx_dly[QR_LATENCY-1][1:0];
    wire       curr_wr_en  = val_dly[QR_LATENCY-1];

    // =========================================================================
    // 3. INPUT MUX 
    // =========================================================================
    reg [31:0] qr_a[0:2], qr_b[0:2], qr_c[0:2], qr_d[0:2];
    
    wire use_diag = (feeding) ? ((feed_cnt == 0 && enable) ? mode : mode_latched) : mode_latched; 
    
    integer k;

    // Pre-calculate indices to clean up MUX logic
    always @(*) begin
        for(k=0; k<3; k=k+1) begin
            // Default 0 to prevent latch inference
            qr_a[k] = 32'd0; qr_b[k] = 32'd0; qr_c[k] = 32'd0; qr_d[k] = 32'd0;
            
            if (use_diag == 1'b0) begin 
                // --- COLUMN MODE ---
                case (feed_cnt[1:0])
                    2'b00: begin qr_a[k] = in_m[0][k]; qr_b[k] = in_m[4][k]; qr_c[k] = in_m[8][k]; qr_d[k] = in_m[12][k]; end
                    2'b01: begin qr_a[k] = in_m[1][k]; qr_b[k] = in_m[5][k]; qr_c[k] = in_m[9][k]; qr_d[k] = in_m[13][k]; end
                    2'b10: begin qr_a[k] = in_m[2][k]; qr_b[k] = in_m[6][k]; qr_c[k] = in_m[10][k]; qr_d[k] = in_m[14][k]; end
                    2'b11: begin qr_a[k] = in_m[3][k]; qr_b[k] = in_m[7][k]; qr_c[k] = in_m[11][k]; qr_d[k] = in_m[15][k]; end
                endcase
            end else begin 
                // --- DIAGONAL MODE ---
                case (feed_cnt[1:0])
                    2'b00: begin qr_a[k] = in_m[0][k]; qr_b[k] = in_m[5][k]; qr_c[k] = in_m[10][k]; qr_d[k] = in_m[15][k]; end
                    2'b01: begin qr_a[k] = in_m[1][k]; qr_b[k] = in_m[6][k]; qr_c[k] = in_m[11][k]; qr_d[k] = in_m[12][k]; end
                    2'b10: begin qr_a[k] = in_m[2][k]; qr_b[k] = in_m[7][k]; qr_c[k] = in_m[8][k]; qr_d[k] = in_m[13][k]; end
                    2'b11: begin qr_a[k] = in_m[3][k]; qr_b[k] = in_m[4][k]; qr_c[k] = in_m[9][k]; qr_d[k] = in_m[14][k]; end
                endcase
            end
        end
    end

    // =========================================================================
    // 4. PIPELINED ARX UNIT (QR)
    // =========================================================================
    wire [31:0] qr_out_a[0:2], qr_out_b[0:2], qr_out_c[0:2], qr_out_d[0:2];

    qr_pipelined_ti_3 qr_inst (
        .clk(clk), .rst(rst), 
        .run_ksa(run_ksa),
        .rand_bits(rand_bits[127:0]), 
        // Inputs
        .a_in_1(qr_a[0]), .a_in_2(qr_a[1]), .a_in_3(qr_a[2]),
        .b_in_1(qr_b[0]), .b_in_2(qr_b[1]), .b_in_3(qr_b[2]),
        .c_in_1(qr_c[0]), .c_in_2(qr_c[1]), .c_in_3(qr_c[2]),
        .d_in_1(qr_d[0]), .d_in_2(qr_d[1]), .d_in_3(qr_d[2]),
        // Outputs
        .a_out_1(qr_out_a[0]), .a_out_2(qr_out_a[1]), .a_out_3(qr_out_a[2]),
        .b_out_1(qr_out_b[0]), .b_out_2(qr_out_b[1]), .b_out_3(qr_out_b[2]),
        .c_out_1(qr_out_c[0]), .c_out_2(qr_out_c[1]), .c_out_3(qr_out_c[2]),
        .d_out_1(qr_out_d[0]), .d_out_2(qr_out_d[1]), .d_out_3(qr_out_d[2])
    );

    // =========================================================================
    // 5. OUTPUT CAPTURE & UNPACKING (OPTIMIZED)
    // =========================================================================
    reg [31:0] out_m_reg [0:15][0:2];
    
    // Loop variables used in the always block
    integer s_idx;
    integer w_init, s_init;

    always @(posedge clk) begin
        // Case 1: Load initial state (When feeding starts)
        // We act like a transparent latch for the whole block at cycle 0 of feeding
        if (feeding && feed_cnt == 0) begin
             // FIX: Verilog does not allow direct array assignment (A <= B) for unpacked arrays.
             // We must iterate through the array.
            for(w_init=0; w_init<16; w_init=w_init+1) begin
                for(s_init=0; s_init<3; s_init=s_init+1) begin
                    out_m_reg[w_init][s_init] <= in_m[w_init][s_init];
                end
            end
        end
        // Case 2: Update specific words
        else if (curr_wr_en) begin
            for(s_idx=0; s_idx<3; s_idx=s_idx+1) begin
                if (mode_latched == 1'b0) begin
                    // --- WRITE BACK COLUMN ---
                    case (curr_wr_idx)
                        2'b00: begin 
                            out_m_reg[0][s_idx]<=qr_out_a[s_idx]; out_m_reg[4][s_idx]<=qr_out_b[s_idx]; 
                            out_m_reg[8][s_idx]<=qr_out_c[s_idx]; out_m_reg[12][s_idx]<=qr_out_d[s_idx]; 
                        end
                        2'b01: begin 
                            out_m_reg[1][s_idx]<=qr_out_a[s_idx]; out_m_reg[5][s_idx]<=qr_out_b[s_idx]; 
                            out_m_reg[9][s_idx]<=qr_out_c[s_idx]; out_m_reg[13][s_idx]<=qr_out_d[s_idx]; 
                        end
                        2'b10: begin 
                            out_m_reg[2][s_idx]<=qr_out_a[s_idx]; out_m_reg[6][s_idx]<=qr_out_b[s_idx]; 
                            out_m_reg[10][s_idx]<=qr_out_c[s_idx]; out_m_reg[14][s_idx]<=qr_out_d[s_idx]; 
                        end
                        2'b11: begin 
                            out_m_reg[3][s_idx]<=qr_out_a[s_idx]; out_m_reg[7][s_idx]<=qr_out_b[s_idx]; 
                            out_m_reg[11][s_idx]<=qr_out_c[s_idx]; out_m_reg[15][s_idx]<=qr_out_d[s_idx]; 
                        end
                    endcase
                end else begin
                    // --- WRITE BACK DIAGONAL ---
                    case (curr_wr_idx)
                        2'b00: begin 
                            out_m_reg[0][s_idx]<=qr_out_a[s_idx]; out_m_reg[5][s_idx]<=qr_out_b[s_idx]; 
                            out_m_reg[10][s_idx]<=qr_out_c[s_idx]; out_m_reg[15][s_idx]<=qr_out_d[s_idx]; 
                        end
                        2'b01: begin 
                            out_m_reg[1][s_idx]<=qr_out_a[s_idx]; out_m_reg[6][s_idx]<=qr_out_b[s_idx]; 
                            out_m_reg[11][s_idx]<=qr_out_c[s_idx]; out_m_reg[12][s_idx]<=qr_out_d[s_idx]; 
                        end
                        2'b10: begin 
                            out_m_reg[2][s_idx]<=qr_out_a[s_idx]; out_m_reg[7][s_idx]<=qr_out_b[s_idx]; 
                            out_m_reg[8][s_idx]<=qr_out_c[s_idx]; out_m_reg[13][s_idx]<=qr_out_d[s_idx]; 
                        end
                        2'b11: begin 
                            out_m_reg[3][s_idx]<=qr_out_a[s_idx]; out_m_reg[4][s_idx]<=qr_out_b[s_idx]; 
                            out_m_reg[9][s_idx]<=qr_out_c[s_idx]; out_m_reg[14][s_idx]<=qr_out_d[s_idx]; 
                        end
                    endcase
                end
            end
        end
    end

    // Unpack output registers to flattened wires
    assign m0x_1=out_m_reg[0][0];   assign m0x_2=out_m_reg[0][1];   assign m0x_3=out_m_reg[0][2];
    assign m1x_1=out_m_reg[1][0];   assign m1x_2=out_m_reg[1][1];   assign m1x_3=out_m_reg[1][2];
    assign m2x_1=out_m_reg[2][0];   assign m2x_2=out_m_reg[2][1];   assign m2x_3=out_m_reg[2][2];
    assign m3x_1=out_m_reg[3][0];   assign m3x_2=out_m_reg[3][1];   assign m3x_3=out_m_reg[3][2];
    assign m4x_1=out_m_reg[4][0];   assign m4x_2=out_m_reg[4][1];   assign m4x_3=out_m_reg[4][2];
    assign m5x_1=out_m_reg[5][0];   assign m5x_2=out_m_reg[5][1];   assign m5x_3=out_m_reg[5][2];
    assign m6x_1=out_m_reg[6][0];   assign m6x_2=out_m_reg[6][1];   assign m6x_3=out_m_reg[6][2];
    assign m7x_1=out_m_reg[7][0];   assign m7x_2=out_m_reg[7][1];   assign m7x_3=out_m_reg[7][2];
    assign m8x_1=out_m_reg[8][0];   assign m8x_2=out_m_reg[8][1];   assign m8x_3=out_m_reg[8][2];
    assign m9x_1=out_m_reg[9][0];   assign m9x_2=out_m_reg[9][1];   assign m9x_3=out_m_reg[9][2];
    assign m10x_1=out_m_reg[10][0]; assign m10x_2=out_m_reg[10][1]; assign m10x_3=out_m_reg[10][2];
    assign m11x_1=out_m_reg[11][0]; assign m11x_2=out_m_reg[11][1]; assign m11x_3=out_m_reg[11][2];
    assign m12x_1=out_m_reg[12][0]; assign m12x_2=out_m_reg[12][1]; assign m12x_3=out_m_reg[12][2];
    assign m13x_1=out_m_reg[13][0]; assign m13x_2=out_m_reg[13][1]; assign m13x_3=out_m_reg[13][2];
    assign m14x_1=out_m_reg[14][0]; assign m14x_2=out_m_reg[14][1]; assign m14x_3=out_m_reg[14][2];
    assign m15x_1=out_m_reg[15][0]; assign m15x_2=out_m_reg[15][1]; assign m15x_3=out_m_reg[15][2];

endmodule