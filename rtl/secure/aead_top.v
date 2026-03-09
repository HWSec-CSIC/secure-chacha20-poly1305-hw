`default_nettype none
// 1st-order masked AEAD ChaCha20-Poly1305 top controller.
// Features guarded Poly evaluation, left-shift data staging,
// SDRR integration, and timing-safe delays.

module aead_core_top_msk #(
    parameter integer SIM               = 0, // 0: Real, 1: Simulation
    parameter integer PIPELINE_STAGES   = 2,
    parameter integer CIPHER_ROUNDS     = 20,
    parameter integer RECURSION_DEPTH   = 0
)(
    input  wire          clk,
    input  wire          rst,
    input  wire          enc,
    input  wire          start,
    input  wire [1:0]    next_blk,
    input  wire [255:0]  key,
    input  wire [95:0]   nonce,
    input  wire [127:0]  aad,
    input  wire [31:0]   aad_len,
    input  wire [511:0]  plaintext,
    input  wire [31:0]   pt_len,
    output reg  [511:0]  ciphertext_sh1,
    output reg  [511:0]  ciphertext_sh2,
    output reg  [511:0]  ciphertext_sh3,
    output reg  [127:0]  tag,
    output reg  [1:0]    valid,
    output reg           ready,
    output reg           busy,
    output reg  [12:0]   busy_cnt,
    output wire [255:0]  prng_key  
);

    // Constants
    localparam NO_OP        = 2'b00;
    localparam AAD_NEXT     = 2'b01;  
    localparam PT_NEXT      = 2'b10;
    localparam AEAD_END     = 2'b11;
    localparam NONE         = 2'b00;
    localparam VALID_CT     = 2'b01;
    localparam VALID_MAC    = 2'b10;
    localparam ctr_initial  = 32'd0;
    
    // Timing Constants
    localparam integer TRIG_CYCLE  = 4;  
    localparam integer HOLD_CYCLES = 12; 
    
    // FSM States
    localparam IDLE         = 5'h00;
    localparam START_PKEY   = 5'h01;
    localparam WAIT_PKEY    = 5'h02;
    localparam GET_PKEY     = 5'h03;
    localparam START_MAC    = 5'h04;
    localparam WAIT_ST_MAC  = 5'h05;
    localparam ADD_AAD      = 5'h06;
    localparam SUM_AAD      = 5'h07;
    localparam WAIT_AAD     = 5'h08;
    localparam WAIT_KS_ACK  = 5'h09; 
    localparam WAIT_VALID_K = 5'h0A;
    localparam GET_CT_1     = 5'h0B;
    localparam GET_CT_2     = 5'h0C; 
    localparam GET_CT_3     = 5'h0D; 
    
    // Processing States
    localparam ADD_PT_BLK0  = 5'h0E;
    localparam WT_PT_BLK0   = 5'h0F;
    localparam ADD_PT_BLK1  = 5'h10;
    localparam WT_PT_BLK1   = 5'h11;
    localparam ADD_PT_BLK2  = 5'h12;
    localparam WT_PT_BLK2   = 5'h13;      
    localparam ADD_PT_BLK3  = 5'h14;
    localparam WT_PT_BLK3   = 5'h15;
    
    localparam ADD_CTRS_END = 5'h16;
    localparam WT_CTRS_END  = 5'h17;
    localparam FINISH_MAC   = 5'h18;
    localparam WAIT_MAC     = 5'h19;
    
    // Internal Signals
    (* DONT_TOUCH = "TRUE" *) wire [511:0] keystream [0:2];
    wire           cc_valid, cc_ready, poly_done, poly_ready;
    (* DONT_TOUCH = "TRUE" *) wire [127:0] poly_mac;
    (* DONT_TOUCH = "TRUE" *) wire [255:0] poly_key [0:2];
    
    // DATA PATH REGISTERS (Protected)
    (* DONT_TOUCH = "TRUE" *) reg  [511:0] data_src_reg [0:2];
    
    reg            cc_init, cc_next_ctr, cc_next;
    reg            poly_start, poly_next, poly_finish;
    reg  [4:0]     state;
    reg            nxt_sect; 
    reg  [63:0]    aad_len_reg, pt_len_reg;
    reg  [63:0]    aad_len_ctr, pt_len_ctr;     
    reg            start_d, start_edg;
    reg            key_is_loaded; 
    reg  [3:0]     delay_ctr;
    reg            ks_phase;

    // PRNG Signals
    wire [532:0] prng_data;      
    wire         prng_valid;          
    
    // Guard & Shift Signals
    reg          poly_msg_gate; 
    reg          shift_left_en;

    // =========================================================================
    // INSTANCES
    // =========================================================================
    (* KEEP_HIERARCHY = "YES" *) chacha20_core_msk #(
        .PIPELINE_STAGES(PIPELINE_STAGES),
        .CIPHER_ROUNDS(CIPHER_ROUNDS)
    ) chacha_inst (
        .clk(clk), .rst(rst),
        .init_ctr(ctr_initial),
        .next_ctr(cc_next_ctr),
        .cc_init(cc_init),
        .cc_next(cc_next),
        .key(key),
        .nonce(nonce),
        .prng_input(prng_data),
        .keystream_sh1(keystream[0]),
        .keystream_sh2(keystream[1]),
        .keystream_sh3(keystream[2]),
        .poly_key_sh1(poly_key[0]),
        .poly_key_sh2(poly_key[1]),
        .poly_key_sh3(poly_key[2]),
        .valid_out(cc_valid),
        .ready(cc_ready)
    );

    // =========================================================================
    // POLY INPUT LOGIC (Guarded & Masked - Optimized for Left Shift)
    // =========================================================================
    
    // 1. Byte Mask Logic
    reg [127:0] current_byte_mask;
    reg [63:0]  current_len_ctr;
    
    // Helper wire
    wire [63:0] pt_rem_after_blk = (pt_len_ctr >= 16) ? (pt_len_ctr - 16) : 64'd0;
    
    function automatic [127:0] le_byte_mask;
      input [5:0] byte_len; 
      integer i;
      begin
        le_byte_mask = 128'b0;
        for (i = 0; i < 16; i = i + 1) begin
          le_byte_mask[((15 - i) * 8) +: 8] = (byte_len == 0 || i < byte_len) ? 8'hFF : 8'h00;
        end
      end
    endfunction  

    always @* begin
        // Determine Length Counter
        if (state == ADD_AAD || state == SUM_AAD) current_len_ctr = aad_len_ctr;
        else if (state == ADD_CTRS_END || state == WT_CTRS_END) current_len_ctr = 64'd16; 
        else begin
            // PT Logic: depends on which block we are in (Standard FSM Logic)
            if (state == ADD_PT_BLK0 || state == WT_PT_BLK0) current_len_ctr = pt_len_ctr;
            else if (state == ADD_PT_BLK1 || state == WT_PT_BLK1) current_len_ctr = pt_rem_after_blk; // Logic from original code
            else if (state == ADD_PT_BLK2 || state == WT_PT_BLK2) current_len_ctr = pt_rem_after_blk; // Simplification, assuming decrements happen
            else current_len_ctr = pt_rem_after_blk;
            // NOTE: Original code used complex nested logic. Here we rely on "current head of shift reg"
            // The FSM decrements pt_len_ctr by 16 AFTER each block.
            // So 'pt_len_ctr' is always correct for the current block being shifted out.
            current_len_ctr = pt_len_ctr; 
        end
        
        // Calculate Mask
        if (current_len_ctr >= 16) current_byte_mask = {128{1'b1}};
        else                       current_byte_mask = le_byte_mask(current_len_ctr[5:0]);
    end

    // 2. Guard Signal (Active during Poly Processing)
    always @(posedge clk) begin
        if (rst) poly_msg_gate <= 0;
        else begin
            // Guard logic matches FSM timing
            if ((state == ADD_AAD && delay_ctr >= 4) || (state == SUM_AAD) || 
                (state == ADD_CTRS_END && delay_ctr >= 4) || (state == WT_CTRS_END) ||
                ((state == ADD_PT_BLK0 || state == ADD_PT_BLK1 || state == ADD_PT_BLK2 || state == ADD_PT_BLK3) && delay_ctr >= 4) ||
                (state == WT_PT_BLK0 || state == WT_PT_BLK1 || state == WT_PT_BLK2 || state == WT_PT_BLK3))
            begin
                poly_msg_gate <= 1'b1;
            end else begin
                poly_msg_gate <= 1'b0;
            end
        end
    end

    // 3. Input Assignments with Guards & Masking
    wire [127:0] poly_in_sh1, poly_in_sh2, poly_in_sh3;
    
    // IMPORTANT: We read from MSB [511:384] because we use Left Shift to bring new data up.
    // This replicates the logic of reading BLK0, then BLK1, etc. from a big register.
    assign poly_in_sh1 = poly_msg_gate ? (data_src_reg[0][511:384] & current_byte_mask) : 128'd0;
    assign poly_in_sh2 = poly_msg_gate ? (data_src_reg[1][511:384] & current_byte_mask) : 128'd0;
    assign poly_in_sh3 = poly_msg_gate ? (data_src_reg[2][511:384] & current_byte_mask) : 128'd0;

    // Debug signal (Do not remove)
    wire [127:0] poly_in_debug;
    assign poly_in_debug = poly_in_sh1 ^ poly_in_sh2 ^ poly_in_sh3;

    (* KEEP_HIERARCHY = "YES" *) poly1305_core_msk #(
        .RECURSION_DEPTH(RECURSION_DEPTH)
    ) poly_inst (
        .clk(clk), .rst(rst),
        .start(poly_start),
        .next(poly_next),
        .finish(poly_finish),
        .prng_input(prng_data),
        .msg_sh1(poly_in_sh1), 
        .msg_sh2(poly_in_sh2),
        .msg_sh3(poly_in_sh3),
        .valid_bytes(3'd0), 
        .key_sh1(poly_key[0]),
        .key_sh2(poly_key[1]),
        .key_sh3(poly_key[2]),
        .mac(poly_mac),
        .valid_out(poly_done),
        .ready(poly_ready)
    );
    
    // =========================================================================
    // PRNG GENERATION
    // =========================================================================
    generate
        if (SIM == 1) begin : gen_prng_sim
            reg  [532:0] prng_data_reg;
            always @(posedge clk) begin
                if (rst) prng_data_reg <= 533'b0;
                else     prng_data_reg <= {$random, $random, $random, $random, $random, $random, $random, $random, $random, $random, $random, $random, $random, $random, $random, $random, $random};
            end
            assign prng_data = prng_data_reg;
            assign prng_valid = 1'b1;
            
        end else begin : gen_prng_real
            trivium_prng #(
                .OUTPUT_LENGTH(540),  
                .TRIVIUM_BITS(180)     
            ) u_prng (
                .clk(clk),
                .rst(rst),
                .en(1'b1),
                .reseed(1'b0),
                .random_data(prng_data),           // Connects to your Masked Core
                .valid(prng_valid)                // Wait for this before starting encryption
            );
        end
    endgenerate
    
    genvar j;
    generate
        for (j = 0; j < 256; j = j + 1) begin : prng_keygen
            assign prng_key[j] = prng_data[2*j] ^ prng_data[2*j+1];
        end
    endgenerate
    
    // =========================================================================
    // 1. DATA SOURCE REGISTERS & LEFT SHIFTER
    // =========================================================================
    
    wire [511:0] rnd_mask_1 = prng_data[511:0];
    wire [511:0] rnd_mask_2 = {prng_data[255:0], ~prng_data[511:256]}; 
    
    reg [127:0] aad_val_masked;
    reg [127:0] ctrs_val_tmp;
    reg [511:0] ct_full;

    always @(posedge clk) begin
        if (rst) begin
            data_src_reg[0] <= 512'd0;
            data_src_reg[1] <= 512'd0;
            data_src_reg[2] <= 512'd0;
        end 
        else begin 
            // -----------------------------------------------------------------
            // LOAD LOGIC
            // -----------------------------------------------------------------
            
            if (state == ADD_AAD) begin
                aad_val_masked = aad & current_byte_mask; 
                // AAD is only 128 bits. We put it in MSB [511:384] to be read first.
                if (delay_ctr == 0) begin
                    data_src_reg[1] <= rnd_mask_1;
                    data_src_reg[2] <= rnd_mask_2;
                    // Put AAD in Top Bits
                    data_src_reg[0] <= {aad_val_masked, 384'd0} ^ rnd_mask_1 ^ rnd_mask_2;
                end
            end
            
            else if (state == ADD_CTRS_END) begin
                ctrs_val_tmp = {
                    aad_len_reg[7:0],    aad_len_reg[15:8],    aad_len_reg[23:16],  aad_len_reg[31:24],
                    aad_len_reg[39:32],  aad_len_reg[47:40],   aad_len_reg[55:48],  aad_len_reg[63:56],
                    pt_len_reg[7:0],     pt_len_reg[15:8],     pt_len_reg[23:16],   pt_len_reg[31:24],
                    pt_len_reg[39:32],   pt_len_reg[47:40],    pt_len_reg[55:48],   pt_len_reg[63:56]
                };
                if (delay_ctr == 0) begin
                    data_src_reg[1] <= rnd_mask_1;
                    data_src_reg[2] <= rnd_mask_2;
                    // Put CTRS in Top Bits
                    data_src_reg[0] <= {ctrs_val_tmp, 384'd0} ^ rnd_mask_1 ^ rnd_mask_2;
                end
            end
            
            else if (state == GET_CT_1) begin
                // Load Ciphertext/Plaintext (512 bits)
                // We load it normally. Original code logic: "first block after aad is last" 
                // implies B3 is LSB and B0 is MSB? 
                // Your old code took poly_msg from bit 511 down to 384 for BLK0.
                // So MSB is First Block.
                
                data_src_reg[1] <= rnd_mask_1;
                data_src_reg[2] <= rnd_mask_2;
                
                if (enc) begin
                    // Encrypt: S0 = PT ^ K0 ^ K1 ^ K2 ^ R1 ^ R2
                    data_src_reg[0] <= (plaintext ^ keystream[0] ^ keystream[1] ^ keystream[2]) ^ rnd_mask_1 ^ rnd_mask_2;
                end 
                else begin
                    // Decrypt: S0 = CT ^ R1 ^ R2
                    data_src_reg[0] <= plaintext ^ rnd_mask_1 ^ rnd_mask_2;
                end
            end 
            
            // -----------------------------------------------------------------
            // LEFT SHIFT LOGIC (Moves Data UP: MSB <- LSB)
            // -----------------------------------------------------------------
            // Triggered between blocks to bring next 128-bit chunk to MSB [511:384]
            else if (shift_left_en) begin
                data_src_reg[0] <= {data_src_reg[0][383:0], 128'd0};
                data_src_reg[1] <= {data_src_reg[1][383:0], 128'd0};
                data_src_reg[2] <= {data_src_reg[2][383:0], 128'd0};
            end
            
            // Idle Clean
            else if (state == IDLE && start_edg) begin
                data_src_reg[0] <= 512'd0; data_src_reg[1] <= 512'd0; data_src_reg[2] <= 512'd0;
            end
        end
    end

    // =========================================================================
    // 3. CIPHERTEXT OUTPUT
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            ciphertext_sh1 <= 512'b0; ciphertext_sh2 <= 512'b0; ciphertext_sh3 <= 512'b0;
        end 
        else begin
            if (enc) begin
                if (state == GET_CT_1) begin
                    // Output needs correct shares.
                    // Keystream is [511:0]. Plaintext is [511:0].
                    // Just XOR them.
                    ciphertext_sh1 <= keystream[0] ^ plaintext; 
                    ciphertext_sh2 <= 512'd0; 
                    ciphertext_sh3 <= 512'd0;
                end 
                else if (state == GET_CT_2) ciphertext_sh2 <= keystream[1]; 
                else if (state == GET_CT_3) ciphertext_sh3 <= keystream[2]; 
            end
            if (state == IDLE && start_edg) begin
                ciphertext_sh1 <= 512'd0; ciphertext_sh2 <= 512'd0; ciphertext_sh3 <= 512'b0;
            end
        end
    end
    
    // Tag storage & Keys (Same as before)
    always @(posedge clk) begin
        if (rst) tag <= 128'b0;
        else if (state == START_PKEY) tag <= prng_data[127:0]; 
        else if (state == WAIT_MAC && poly_done) tag <= poly_mac;
    end
    always @(posedge clk) begin
        if (rst) key_is_loaded <= 1'b0;
        else if (state == GET_PKEY) key_is_loaded <= 1'b1; 
        else if (state == WAIT_MAC) key_is_loaded <= 1'b0; 
    end
    
    // Length Counters (Same as before)
    always @(posedge clk) begin
        if (rst) begin
                aad_len_reg  <= 64'b0; aad_len_ctr  <= 64'b0;
                pt_len_reg   <= 64'b0; pt_len_ctr   <= 64'b0;
        end else if (state == START_PKEY) begin
                aad_len_ctr  <= {32'b0, aad_len};
                aad_len_reg  <= {32'b0, aad_len};
                pt_len_ctr   <= {32'b0, pt_len};  pt_len_reg   <= {32'b0, pt_len};
        end 
        else if (state == ADD_AAD && poly_next) begin 
                if (aad_len_ctr < 64'd16)   aad_len_ctr  <= 64'd0;
                else                        aad_len_ctr  <= aad_len_ctr - 64'd16; 
        end 
        else if ((state == ADD_PT_BLK0 || state == ADD_PT_BLK1 || state == ADD_PT_BLK2 || state == ADD_PT_BLK3) && poly_next) begin 
                if (pt_len_ctr < 64'd16) pt_len_ctr <= 64'd0;
                else                     pt_len_ctr <= pt_len_ctr - 64'd16;
        end
    end 
    
    // Edge & Valid (Same as before)
    always @(posedge clk) begin
        if (rst) begin start_d <= 1'b0; start_edg <= 1'b0; end 
        else begin start_edg <= start & ~start_d; start_d <= start; end
    end
    always @(posedge clk) begin
    if (rst) valid <= NONE;
    else begin
        valid <= NONE;
        if (state == GET_CT_3) valid <= VALID_CT; 
        else if (state == WAIT_MAC && poly_done) valid <= VALID_MAC;
    end
    end
        
    // =========================================================================
    // MAIN FSM (Legacy Structure + Shift Control)
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            cc_init <= 0; cc_next_ctr <= 0; cc_next <= 0;
            poly_start <= 0; poly_next <= 0; poly_finish <= 0;
            ready <= 0; nxt_sect <= 0; state <= IDLE;
            ks_phase <= 1'b0; busy <= 1'b0; delay_ctr <= 0;
            shift_left_en <= 0;
        end 
        else begin
            cc_init <= 0; cc_next_ctr <= 0; cc_next <= 0;
            poly_start <= 0; poly_next <= 0; poly_finish <= 0;
            ready <= 0; shift_left_en <= 0;

            case (state)
                IDLE: begin 
                    ready <= 1'b1;
                    if (start_edg && next_blk == 0 && !key_is_loaded && prng_valid) begin    
                        cc_init     <= 1'b1; ks_phase <= 1'b1; state <= START_PKEY; 
                        nxt_sect    <= (aad_len == 0); busy <= 1'b1;
                    end 
                    else if (((start_edg && next_blk == AAD_NEXT) || (aad_len_ctr > 64'd0 && key_is_loaded)) && prng_valid) begin
                        state <= ADD_AAD; delay_ctr <= 0;
                    end 
                    else if (start_edg && next_blk == PT_NEXT && prng_valid) begin    
                        if (ks_phase == 1'b0) begin cc_next <= 1'b1; ks_phase <= 1'b1; end 
                        else begin cc_next_ctr <= 1'b1; ks_phase <= 1'b0; end
                        state <= WAIT_KS_ACK;
                    end 
                    else if (((start_edg && next_blk == AEAD_END) || (busy && aad_len_ctr == 32'd0 && pt_len_ctr == 32'b0 && key_is_loaded)) && prng_valid) begin
                        state <= ADD_CTRS_END; delay_ctr <= 0;
                    end                            
                end
                
                START_PKEY: begin state <= WAIT_PKEY; end
                WAIT_KS_ACK: begin if (!cc_valid) state <= WAIT_VALID_K; end
                WAIT_VALID_K: begin if (cc_valid) state <= GET_CT_1; end
                WAIT_PKEY:  begin if(cc_valid) state <= GET_PKEY; end 
                GET_PKEY:   begin state <= START_MAC; end
                START_MAC:  begin poly_start <= 1'b1; if(!poly_ready) state <= WAIT_ST_MAC; end
                
                WAIT_ST_MAC: begin
                    if (poly_ready) begin
                        if (!nxt_sect) state <= ADD_AAD;
                        else begin cc_next_ctr <= 1'b1; ks_phase <= 1'b0; state <= WAIT_KS_ACK; end
                    end
                end
                
                ADD_AAD: begin 
                    if (poly_ready || delay_ctr > 0) begin
                        if (delay_ctr == TRIG_CYCLE) poly_next <= 1;
                        if (delay_ctr < HOLD_CYCLES) delay_ctr <= delay_ctr + 1;
                        else begin state <= SUM_AAD; delay_ctr <= 0; end
                    end
                end
                SUM_AAD: state <= WAIT_AAD;
                WAIT_AAD: begin
                    if (poly_ready) begin
                        if (aad_len_ctr > 0) state <= ADD_AAD; 
                        else if (pt_len_ctr > 0) begin cc_next_ctr <= 1'b1; ks_phase <= 1'b0; state <= WAIT_KS_ACK; end 
                        else state <= IDLE;
                    end
                end
                
                GET_CT_1: state <= GET_CT_2;
                GET_CT_2: state <= GET_CT_3;
                GET_CT_3: begin state <= ADD_PT_BLK0; delay_ctr <= 0; end
                
                // BLK0 (Reads MSB [511:384])
                ADD_PT_BLK0: begin 
                    if (poly_ready || delay_ctr > 0) begin
                        if (pt_len_ctr == 0 && delay_ctr == 0) begin poly_next <= 1; state <= IDLE; delay_ctr <= 0; end 
                        else begin
                            if (delay_ctr == TRIG_CYCLE) poly_next <= 1;
                            if (delay_ctr < HOLD_CYCLES) delay_ctr <= delay_ctr + 1;
                            else begin state <= WT_PT_BLK0; delay_ctr <= 0; end
                        end
                    end
                end
                WT_PT_BLK0: begin 
                    if (poly_ready) begin
                        shift_left_en <= 1'b1; // SHIFT LEFT: BLK1 moves to MSB
                        if (pt_len_ctr < 64'd16) state <= IDLE;
                        else state <= ADD_PT_BLK1;
                    end
                end
                
                // BLK1 (Reads MSB [511:384] again, which is now BLK1)
                ADD_PT_BLK1: begin 
                    if (poly_ready || delay_ctr > 0) begin
                        if (delay_ctr == TRIG_CYCLE) poly_next <= 1;
                        if (delay_ctr < HOLD_CYCLES) delay_ctr <= delay_ctr + 1;
                        else begin state <= WT_PT_BLK1; delay_ctr <= 0; end
                    end
                end
                WT_PT_BLK1: begin
                    if (poly_ready) begin
                        shift_left_en <= 1'b1; // SHIFT LEFT: BLK2 moves to MSB
                        if (pt_len_ctr < 64'd16) state <= IDLE;
                        else state <= ADD_PT_BLK2;
                    end
                end
                
                // BLK2
                ADD_PT_BLK2: begin 
                    if (poly_ready || delay_ctr > 0) begin
                        if (delay_ctr == TRIG_CYCLE) poly_next <= 1;
                        if (delay_ctr < HOLD_CYCLES) delay_ctr <= delay_ctr + 1;
                        else begin state <= WT_PT_BLK2; delay_ctr <= 0; end
                    end
                end
                WT_PT_BLK2: begin
                    if (poly_ready) begin
                        shift_left_en <= 1'b1; // SHIFT LEFT: BLK3 moves to MSB
                        if (pt_len_ctr < 64'd16) state <= IDLE;
                        else state <= ADD_PT_BLK3;
                    end
                end

                // BLK3
                ADD_PT_BLK3: begin 
                    if (poly_ready || delay_ctr > 0) begin
                        if (delay_ctr == TRIG_CYCLE) poly_next <= 1;
                        if (delay_ctr < HOLD_CYCLES) delay_ctr <= delay_ctr + 1;
                        else begin state <= WT_PT_BLK3; delay_ctr <= 0; end
                    end
                end
                WT_PT_BLK3: begin
                    if (poly_ready) begin
                         // No shift needed, all done
                        if (pt_len_ctr > 0) begin cc_next_ctr <= 1'b1; ks_phase <= 1'b0; state <= WAIT_KS_ACK; end 
                        else state <= IDLE;
                    end
                end
                
                ADD_CTRS_END: begin 
                    if (poly_ready || delay_ctr > 0) begin
                        if (delay_ctr == TRIG_CYCLE) poly_next <= 1;
                        if (delay_ctr < HOLD_CYCLES) delay_ctr <= delay_ctr + 1;
                        else begin state <= WT_CTRS_END; delay_ctr <= 0; end
                    end
                end
                WT_CTRS_END: begin if (poly_ready) state <= FINISH_MAC; end
                FINISH_MAC:   if (poly_ready) begin poly_finish <= 1; state <= WAIT_MAC; end
                WAIT_MAC:     if (poly_done) begin state <= IDLE; busy <= 1'b0; end
                
                default: state <= IDLE;
            endcase
        end
    end
    
    // Busy Counter
    always @(posedge clk) begin
        if (rst) begin busy_cnt <= 13'd0; end 
        else begin
            if (busy) begin if (busy_cnt < 13'h1FFF) busy_cnt <= busy_cnt + 1; end 
            else if (start_edg) busy_cnt <= 0;
        end
    end
    
endmodule