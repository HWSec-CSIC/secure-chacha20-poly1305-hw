`default_nettype none
// Masked Poly1305 MAC engine with SDRR B2A gadgets, blinded Karatsuba
// multiplier, and dummy operation injection for SCA resistance.

module poly1305_core_msk #(
    parameter RECURSION_DEPTH = 1
)(
    input  wire             clk,
    input  wire             rst,
    input  wire             start,
    input  wire             next,
    input  wire             finish,
    input  wire [532:0]     prng_input, 
    input  wire [127:0]     msg_sh1, msg_sh2, msg_sh3,
    input  wire [2:0]       valid_bytes,
    input  wire [255:0]     key_sh1, key_sh2, key_sh3,
    output wire [127:0]     mac,
    output reg              valid_out,
    output wire             ready
);

    // FSM states
    localparam  IDLE     = 4'h0,
                MSK_S    = 4'h1,
                MSK_R    = 4'h2,
                MSK_ACC  = 4'h3,
                ADD_PAD  = 4'h4,
                ADD_SUM  = 4'h5,
                ADD_SUB  = 4'h6,
                ADD_COMP = 4'h7,
                ST_MUL   = 4'h8,
                WAIT_MUL = 4'h9,
                END_MUL  = 4'hA,
                ADD_END  = 4'hB,
                FINAL_RED= 4'hD,
                END_MAC  = 4'hC;
    
    localparam [130:0] P = {1'b1, 130'b0} - 5; 
    localparam [127:0] CLAMP_MASK = 128'h0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF;
    localparam [7:0]   DLY_CYCLS = 8'd2;
    localparam [3:0]   ACC_DLY = 4'd10;

    (* DONT_TOUCH = "TRUE" *) reg [130:0] acc [0:1];                   
    reg [127:0] mac_reg;                    
    reg [3:0]   state;
    
    // --- SDRR step counter ---
    reg [1:0] step_cnt;

    // Stable registers
    (* DONT_TOUCH = "TRUE" *) reg [129:0] n_blk_0_stable, n_blk_1_stable;
    (* DONT_TOUCH = "TRUE" *) reg [129:0] r_side_0_stable, r_side_1_stable;
    (* DONT_TOUCH = "TRUE" *) reg [129:0] s_side_0_stable, s_side_1_stable;

    // Oscillating wires
    (* DONT_TOUCH = "TRUE" *) wire [129:0] n_blk_raw;
    (* DONT_TOUCH = "TRUE" *) wire [129:0] r_side_0_raw;
    (* DONT_TOUCH = "TRUE" *) wire [129:0] s_side_0_raw;

    // Multiplier interface
    wire [129:0] r_side [0:1]; 
    wire [129:0] s_side [0:1];
    (* DONT_TOUCH = "TRUE" *) wire [133:0] a_mul [0:3]; 
    
    assign r_side[0] = r_side_0_stable; 
    assign r_side[1] = r_side_1_stable;
    assign s_side[0] = s_side_0_stable; 
    assign s_side[1] = s_side_1_stable;

    // --- CONTROL SDRR (Delay 3 cycl) ---
    reg sdrr_sel;
    always @(posedge clk) begin
        if (rst) sdrr_sel <= 1'b0;
        else begin
            if (state == MSK_S || state == MSK_R || state == ADD_PAD) begin
                if (step_cnt == 2'd0) sdrr_sel <= 1'b1;
                else                  sdrr_sel <= 1'b0;
            end 
            else sdrr_sel <= 1'b0;
        end  
    end

    // Entropy Binding
    wire [129:0] p_noise_1 = {prng_input[129:0]};
    wire [129:0] p_noise_2 = {prng_input[259:130]};
    wire [129:0] p_noise_3 = {prng_input[389:260]};
    wire [129:0] p_noise_4 = {prng_input[519:390]}; 

    // Acc shares operation delay counter
    reg [3:0]    acc_delay_ctr;
    
    // =========================================================================
    // RECOMBINATION LOGIC (SCA: dummy injection)
    // =========================================================================

    // 3. Pipeline control
    localparam PIPE_LATENCY = 2;
    localparam DUMMY_IDX    = 4'd5; // Insert dummy op halfway between 0 and 10

    // Detect if we are in the "Dummy" cycle
    wire trig_dummy = (state == ADD_END) && (acc_delay_ctr == DUMMY_IDX);

    // Trigger pipeline for Acc0, Acc1, OR the Dummy Op
    wire pipe_trig = (state == ADD_END) && 
                    ((acc_delay_ctr == 4'd0) || (acc_delay_ctr == ACC_DLY) || trig_dummy);
    
    // Select inputs: Standard logic vs Dummy Randomness
    wire use_acc1_inputs = (acc_delay_ctr >= 4'd4); 

    // Muxing: If trig_dummy is high, inject noise. Otherwise, use standard logic.
    wire [133:0] mux_in_a = trig_dummy      ? {4'b0, p_noise_1} : // SCA: Dummy Data A
                            use_acc1_inputs ? a_mul[2] : a_mul[0];

    wire [133:0] mux_in_b = trig_dummy      ? {4'b0, p_noise_2} : // SCA: Dummy Data B
                            use_acc1_inputs ? a_mul[3] : a_mul[1];

    wire         mux_sub  = trig_dummy      ? p_noise_4[0] :      // SCA: Random sub flag
                            use_acc1_inputs; 

    // Module output
    wire [130:0] pipe_res_out;

    // 4. Pipeline module instance
    (* KEEP_HIERARCHY = "YES" *) poly1305_recombine_pipe u_recombine_pipe (
        .clk(clk),
        .rst(rst),
        .en(pipe_trig),          
        .in_a(mux_in_a),
        .in_b(mux_in_b),
        .noise_1({prng_input[523:520], p_noise_1}),
        .noise_2({prng_input[527:524], p_noise_2}),
        .noise(current_noise_U),   //.noise(p_noise_3), 
        .sub_noise(mux_sub),
        .result_share(pipe_res_out)
    );

    // =========================================================================
    // 1. DATA PREPARATION
    // =========================================================================
    function [129:0] fmt_le (input [127:0] in);
        fmt_le = { 2'b00, in[7:0], in[15:8], in[23:16], in[31:24], in[39:32], in[47:40], in[55:48], in[63:56], in[71:64], in[79:72], in[87:80], in[95:88], in[103:96],in[111:104],in[119:112],in[127:120] };
    endfunction
    function [129:0] fmt_key_r (input [255:0] k);
        fmt_key_r = { 2'b00, k[135:128], k[143:136], k[151:144], k[159:152], k[167:160], k[175:168], k[183:176], k[191:184], k[199:192], k[207:200], k[215:208], k[223:216], k[231:224], k[239:232], k[247:240], k[255:248] };
    endfunction

    reg [127:0] valid_data_mask;
    always @* begin
        if (valid_bytes == 3'd0) valid_data_mask = {128{1'b1}};
        else valid_data_mask = ~({128{1'b1}} << (valid_bytes * 8)); 
    end
    
    wire [129:0] padding_bit_mask;
    assign padding_bit_mask = (130'b1 << ((valid_bytes == 3'd0) ? 128 : (valid_bytes * 8)));

    wire [129:0] msg_sh1_fmt = fmt_le(msg_sh1 & valid_data_mask);
    wire [129:0] msg_sh2_fmt = fmt_le(msg_sh2 & valid_data_mask);
    wire [129:0] msg_sh3_fmt = fmt_le(msg_sh3 & valid_data_mask);
    wire [129:0] key_r_sh1_fmt = fmt_key_r(key_sh1);
    wire [129:0] key_r_sh2_fmt = fmt_key_r(key_sh2);
    wire [129:0] key_r_sh3_fmt = fmt_key_r(key_sh3);
    wire [129:0] key_s_sh1_fmt = fmt_le(key_sh1[127:0]);
    wire [129:0] key_s_sh2_fmt = fmt_le(key_sh2[127:0]);
    wire [129:0] key_s_sh3_fmt = fmt_le(key_sh3[127:0]);

    // =========================================================================
    // 2. B2A GADGETS
    // =========================================================================
    
    (* KEEP_HIERARCHY = "YES" *) b2a_sdrr_universal_gadget #(.MOD_P_OP(1)) u_gadget_nblk (
        .clk(clk), .rst(rst), .sel(sdrr_sel),
        .sh1(msg_sh1_fmt), .sh2(msg_sh2_fmt), .sh3(msg_sh3_fmt),
        .arith_mask(p_noise_4), 
        .noise_1(p_noise_1), .noise_2(p_noise_2), .noise_3(p_noise_3),
        .logic_and_mask({130{1'b1}}), .logic_or_mask(padding_bit_mask), 
        .val_out_oscillating(n_blk_raw)
    );

    (* KEEP_HIERARCHY = "YES" *) b2a_sdrr_universal_gadget #(.MOD_P_OP(1)) u_gadget_r (
        .clk(clk), .rst(rst), .sel(sdrr_sel),
        .sh1(key_r_sh1_fmt), .sh2(key_r_sh2_fmt), .sh3(key_r_sh3_fmt),
        .arith_mask(p_noise_4),
        .noise_1(p_noise_1), .noise_2(p_noise_2), .noise_3(p_noise_3),
        .logic_and_mask({2'b00, CLAMP_MASK}), .logic_or_mask(130'd0),               
        .val_out_oscillating(r_side_0_raw)
    );

   (* KEEP_HIERARCHY = "YES" *) b2a_sdrr_universal_gadget #(.MOD_P_OP(0)) u_gadget_s (
        .clk(clk), .rst(rst), .sel(sdrr_sel),
        .sh1(key_s_sh1_fmt), .sh2(key_s_sh2_fmt), .sh3(key_s_sh3_fmt),
        .arith_mask(p_noise_4),
        .noise_1(p_noise_1), .noise_2(p_noise_2), .noise_3(p_noise_3),
        .logic_and_mask({130{1'b1}}), .logic_or_mask(130'd0),        
        .val_out_oscillating(s_side_0_raw)
    );

    // =========================================================================
    // 3. SYNCHRONIZED CAPTURE
    // =========================================================================
    always @(posedge clk) begin
        if (rst) begin
            n_blk_0_stable <= 0; n_blk_1_stable <= 0;
            r_side_0_stable <= 0; r_side_1_stable <= 0;
            s_side_0_stable <= 0; s_side_1_stable <= 0;
        end else begin 
            // Random Share
            if (step_cnt == 2'd1) begin
                if (state == ADD_PAD) n_blk_1_stable    <= p_noise_4;
                if (state == MSK_S)   s_side_1_stable   <= p_noise_4;
                if (state == MSK_R)   r_side_1_stable   <= p_noise_4;
            end
            
            // Arithmetic calculated share
            else if (step_cnt == 2'd0) begin
                if (state == ADD_SUM) n_blk_0_stable <= n_blk_raw; 
                if (state == MSK_R)   s_side_0_stable <= s_side_0_raw; 
                if (state == MSK_ACC) r_side_0_stable <= r_side_0_raw; 
            end
        end
    end

    // =========================================================================
    // 4. CORE LOGIC
    // =========================================================================

    wire [3:0] mul_rdy;
    reg  [3:0] mul_st;
    genvar i;
    generate 
        for (i = 0; i < 4; i = i + 1) begin : shares_gen
            (* KEEP_HIERARCHY = "YES" *) poly1305_mul_mod_opt #( .RECURSION_DEPTH(RECURSION_DEPTH) ) mul_mod_module (
                .clk(clk), .rst(rst),
                .start(mul_st[i]),
                .A(r_side[i%2]), .B(acc[i/2][129:0]), .Zrw(a_mul[i]), .ready(mul_rdy[i]),
                .prng_noise(prng_input[259:130] ^ {130{i[0]}})
            );
        end
    endgenerate

    reg [7:0] delay_cnt; 
    always @(posedge clk) begin
        if (rst) begin mul_st <= 4'd0; delay_cnt <= 8'd0; end
        else begin
            if (state == ADD_COMP) begin
                if (acc_delay_ctr == ACC_DLY) begin
                    mul_st <= 4'd1;
                end else begin
                    mul_st <= 4'd0;
                end
                delay_cnt <= 8'd0;
            end
            else if (state == ST_MUL) begin 
                if (delay_cnt >= DLY_CYCLS) begin mul_st <= mul_st << 1; delay_cnt <= 8'd0; end 
                else delay_cnt <= delay_cnt + 1; 
            end
            else if (state == WAIT_MUL) begin mul_st <= 4'd0; delay_cnt <= 8'd0; end
        end
    end
    
    
    // Noise sum addition register logic
    (* DONT_TOUCH = "TRUE" *) reg [129:0] current_noise_U;
    
    always @(posedge clk) begin
        if (rst) begin
            current_noise_U <= 0;
        end 
        else begin
            if (state == END_MUL) begin                
                current_noise_U <= p_noise_3;
            end
        end
    end

    // =========================================================================
    // 5.1 PARTIAL MODULAR REDUCTION (ADD_COMP) - GUARDED
    // =========================================================================
    
    // Only allow bits through the addition logic when in ADD_COMP state.
    // Otherwise, zero the input to silence the adder.
    wire run_comp = (state == ADD_COMP);

    // --- SHARE 0 ---
    // Isolation mux
    (* KEEP="TRUE" *) wire [130:0] acc0_comp_in = run_comp ? acc[0] : 131'd0;

    wire [129:0] acc0_lower = acc0_comp_in[129:0];
    wire         acc0_msb   = acc0_comp_in[130];
    wire [2:0]   acc0_correction = {acc0_msb, 2'b00} + acc0_msb; 
    
    (* KEEP="TRUE", DONT_TOUCH="TRUE" *) wire [129:0] acc0_comp_next;
    assign acc0_comp_next = acc0_lower + acc0_correction;
    
    // --- SHARE 1 ---
    // Isolation mux
    (* KEEP="TRUE" *) wire [130:0] acc1_comp_in = run_comp ? acc[1] : 131'd0;

    wire [129:0] acc1_lower = acc1_comp_in[129:0];
    wire         acc1_msb   = acc1_comp_in[130];
    wire [2:0]   acc1_correction = {acc1_msb, 2'b00} + acc1_msb; 
    
    (* KEEP="TRUE", DONT_TOUCH="TRUE" *) wire [129:0] acc1_comp_next;
    assign acc1_comp_next = acc1_lower + acc1_correction;


    // -------------------------------------------------------------------------
    // Stage 1 (FINAL_RED): Folding and comparison - GUARDED
    // -------------------------------------------------------------------------
    
    // Control signal: only activate this logic in FINAL_RED
    wire run_final = (state == FINAL_RED);

    // Use current_noise_U (stable) instead of p_noise_4 (live)
    // to avoid collisions with register cleanup in ADD_END.
    wire [130:0] full_blind_noise = run_final ? current_noise_U : 131'd0; 
    
    // Accumulator input isolation
    (* KEEP="TRUE" *) wire [130:0] acc0_final_in = run_final ? acc[0] : 131'd0;
    (* KEEP="TRUE" *) wire [130:0] acc1_final_in = run_final ? acc[1] : 131'd0;

    
    // Operate on "final_in" signals which are 0 outside FINAL_RED
    wire [130:0] acc0_folded = acc0_final_in[129:0] + (acc0_final_in[130] * 3'd5);
    wire [130:0] acc1_folded = acc1_final_in[129:0] + (acc1_final_in[130] * 3'd5);
    
    // 2. Add Mask
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [132:0] total_folded_masked;
    assign total_folded_masked = acc0_folded + acc1_folded + full_blind_noise;
    
    // 3. Threshold Comparison
    wire [131:0] p_blinded_linear = {1'b0, P} + {2'b0, full_blind_noise};
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire condition_blinded;
    assign condition_blinded = (total_folded_masked >= p_blinded_linear);

    // --- REGISTROS DE PIPELINE ---
    (* DONT_TOUCH = "TRUE" *) reg [132:0] pipe_acc_total;
    (* DONT_TOUCH = "TRUE" *) reg         pipe_needs_reduction;
    (* DONT_TOUCH = "TRUE" *) reg [129:0] pipe_final_mask;

    // -------------------------------------------------------------------------
    // Stage 2 (END_MAC): Final reduction - GUARDED
    // -------------------------------------------------------------------------
    
    // Only activate in END_MAC to save power and avoid glitches
    wire run_end_mac = (state == END_MAC);

    // Pipeline register isolation
    (* KEEP="TRUE" *) wire [132:0] pipe_total_guarded = run_end_mac ? pipe_acc_total : 133'd0;
    (* KEEP="TRUE" *) wire [129:0] pipe_mask_guarded  = run_end_mac ? pipe_final_mask : 130'd0;
    
    // If condition is true, subtract P
    wire [132:0] res_reduced = pipe_total_guarded - P;
    
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [132:0] final_val_masked;
    // Use pipe_needs_reduction directly (1 bit, low risk) or guarded
    assign final_val_masked = (run_end_mac && pipe_needs_reduction) ? res_reduced : pipe_total_guarded;

    // Key S addition (isolate S to prevent leakage)
    (* KEEP="TRUE" *) wire [129:0] s0_guarded = run_end_mac ? s_side_0_stable : 130'd0;
    (* KEEP="TRUE" *) wire [129:0] s1_guarded = run_end_mac ? s_side_1_stable : 130'd0;

    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [132:0] mac_stage_1 = final_val_masked + s0_guarded;
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [132:0] mac_stage_2 = mac_stage_1 + s1_guarded;
    
    // Final unmasking
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [132:0] mac_clear_wide = mac_stage_2 - pipe_mask_guarded;
    wire [130:0] mac_clear = mac_clear_wide[130:0];
    
    // ACCUMULATOR REGISTER
    always @(posedge clk) begin
        if (rst || state == MSK_R) begin 
            acc[0] <= 0; acc[1] <= 0; 
            mac_reg <= p_noise_3;
        end 
        else begin 
            if (state == MSK_ACC) begin 
                acc[1] <= p_noise_1; 
                acc[0] <= P - p_noise_1; 
            end 
            else if (state == ADD_SUB) begin 
                // Message addition (SDRR)
                if (acc_delay_ctr == 4'b0) begin
                    acc[0] <= acc[0] + n_blk_0_stable; 
                    acc[1] <= acc[1];
                end else if (acc_delay_ctr == ACC_DLY) begin
                    acc[0] <= acc[0];
                    acc[1] <= acc[1] + n_blk_1_stable; 
                end              
            end 
            else if (state == ADD_COMP) begin 
                // Partial compression
                if (acc_delay_ctr == 4'b0) begin
                    acc[0] <= {1'b0, acc0_comp_next}; 
                    acc[1] <= acc[1];
                end else if (acc_delay_ctr == ACC_DLY) begin
                    acc[0] <= acc[0];
                    acc[1] <= {1'b0, acc1_comp_next}; 
                end 
            end 
            else if (state == ADD_END) begin 
                if (acc_delay_ctr == (4'd0 + PIPE_LATENCY - 1)) begin
                    acc[0] <= p_noise_4; 
                end 
                else if (acc_delay_ctr == (4'd0 + PIPE_LATENCY)) begin
                    acc[0] <= pipe_res_out; 
                end 
                if (acc_delay_ctr == (ACC_DLY + PIPE_LATENCY - 1)) begin
                    acc[1] <= p_noise_4; 
                end 
                else if (acc_delay_ctr == (ACC_DLY + PIPE_LATENCY)) begin
                    acc[1] <= pipe_res_out; 
                end 
            end
            else if (state == FINAL_RED) begin
                pipe_acc_total       <= total_folded_masked;
                pipe_needs_reduction <= condition_blinded;
                pipe_final_mask      <= full_blind_noise; 
            end
            else if (state == END_MAC) begin
                mac_reg <= fmt_le(mac_clear);
            end
        end
    end

    // FSM Control 
    always@(posedge clk) begin
        if (rst) begin 
            state <= IDLE; 
            step_cnt <= 0; 
            acc_delay_ctr <= 0;
        end
        else begin 
            acc_delay_ctr <= acc_delay_ctr + 1'b1;
            case(state)
                IDLE: begin
                    step_cnt <= 0; 
                    if (start) begin
                        state <= MSK_S;
                        step_cnt <= 0; 
                    end
                    else if (next) begin
                        state <= ADD_PAD;
                        step_cnt <= 0; 
                    end
                    else if (finish) begin
                        state <= FINAL_RED;
                        step_cnt <= 0; 
                    end
                end
                
                MSK_S: begin
                    if (step_cnt < 2) step_cnt <= step_cnt + 1;
                    else begin step_cnt <= 0; state <= MSK_R; end 
                end
                
                MSK_R: begin
                    if (step_cnt < 2) step_cnt <= step_cnt + 1;
                    else begin step_cnt <= 0; state <= MSK_ACC; end
                end
                
                MSK_ACC: begin
                    if (step_cnt < 2) step_cnt <= step_cnt + 1;
                    else begin step_cnt <= 0; state <= IDLE; end
                end
                
                ADD_PAD: begin
                    if (step_cnt < 2) step_cnt <= step_cnt + 1;
                    else begin step_cnt <= 0; state <= ADD_SUM; end
                end
                
                ADD_SUM: begin
                    if (step_cnt < 2) step_cnt <= step_cnt + 1;
                    else begin step_cnt <= 0; state <= ADD_SUB; acc_delay_ctr <= 0; end
                end
                
                ADD_SUB:  begin
                    if (acc_delay_ctr == ACC_DLY) begin
                        state <= ADD_COMP; 
                        acc_delay_ctr <= 0;
                    end
                end    
                
                ADD_COMP:  begin
                    if (acc_delay_ctr == ACC_DLY) begin
                        state <= ST_MUL; 
                        acc_delay_ctr <= 0;
                    end
                end 
                
                ST_MUL:   if (mul_st  == 4'b0000) state <= WAIT_MUL;
                WAIT_MUL: if (mul_rdy == 4'b1111) state <= END_MUL;
                END_MUL:  begin
                    state <= ADD_END;
                    acc_delay_ctr <= 0; 
                end
                
                ADD_END:  begin
                    if (!next && acc_delay_ctr == (ACC_DLY + PIPE_LATENCY)) begin
                        state <= IDLE;
                        acc_delay_ctr <= 0;
                    end
                end
                
                FINAL_RED: begin
                    state <= END_MAC;
                end
                
                END_MAC:  if (!finish) state <= IDLE;
                default:  state <= IDLE;
            endcase
        end
    end        
    
    always @(posedge clk) begin if (rst) valid_out <= 1'b0; else if (state == MSK_S) valid_out <= 1'b0; else if (state == END_MAC) valid_out <= 1'b1; end 
    assign mac = mac_reg; assign ready = (state == IDLE);
    
endmodule

// =============================================================================
// SUB-MODULES
// =============================================================================

(* KEEP_HIERARCHY = "YES" *) 
module poly1305_mul_mod_opt #(
    parameter RECURSION_DEPTH = 1
)(  
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    output wire         ready,
    input  wire [129:0] A,
    input  wire [129:0] B,
    input  wire [129:0] prng_noise, 
    output wire [133:0] Zrw         
);
    
    localparam IDLE     = 3'b000;
    localparam ST_MUL   = 3'b001;
    localparam END_MUL  = 3'b010;
    localparam LATCH_RES= 3'b011; 
    localparam DONE     = 3'b100;
    
    reg [2:0] state;
    (* DONT_TOUCH = "TRUE" *) reg [133:0] Zr;
    
    reg mult_start;
    wire mult_ready;

    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [259:0] mult_result;
    
    (* DONT_TOUCH = "TRUE" *) karatsuba_multiplier #(
        .WIDTH(130),
        .RECURSION_DEPTH(RECURSION_DEPTH)
    ) karatsuba_mult (
        .clk(clk), .rst(rst),
        .start(mult_start), .ready(mult_ready),
        .A(A), .B(B), .result(mult_result), .prng_noise(prng_noise)
    );
    
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [129:0] high_part = mult_result[259:130];
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [129:0] low_part  = mult_result[129:0];
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [132:0] high_times_5;
    assign high_times_5 = {high_part, 2'b00} + high_part;
    
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [133:0] folded_result_wire;
    assign folded_result_wire = high_times_5 + low_part;

    assign Zrw = Zr;
    assign ready = (state == IDLE || state == DONE);
    
    always @(posedge clk) begin
        if (rst) begin
            state      <= IDLE;
            mult_start <= 1'b0;
            Zr         <= 0;
        end else begin 
            case (state)
                IDLE: begin
                    if (start && ready) begin
                        mult_start <= 1'b1;
                        state      <= ST_MUL;
                    end
                end

                ST_MUL: begin
                    mult_start <= 1'b0;
                    state      <= END_MUL;
                end
                
                END_MUL: begin
                    if (mult_ready) begin
                        state <= LATCH_RES;
                    end
                end

                LATCH_RES: begin
                    Zr    <= folded_result_wire; 
                    state <= DONE;
                end

                DONE: begin
                    state <= IDLE;
                end

                default: state <= IDLE;
            endcase
        end
    end
endmodule

(* KEEP_HIERARCHY = "YES" *)
module karatsuba_multiplier #(
    parameter WIDTH = 130,
    parameter RECURSION_DEPTH = 1
)(
    input  wire               clk,
    input  wire               rst,
    input  wire               start,
    output wire               ready,
    input  wire [WIDTH-1:0]   A,
    input  wire [WIDTH-1:0]   B,
    input  wire [WIDTH-1:0]   prng_noise,
    output wire [2*WIDTH-1:0] result
);

    localparam HALF_WIDTH = (WIDTH + 1) >> 1;
    localparam USE_RECURSION = (RECURSION_DEPTH > 0) && (WIDTH > 16);
    
    localparam IDLE     = 4'b0000;
    localparam WAIT_Z0  = 4'b0001;
    localparam CALC_Z0  = 4'b0010;
    localparam WAIT_Z2  = 4'b0011;
    localparam CALC_Z2  = 4'b0100;
    localparam WAIT_M   = 4'b0101;
    localparam CALC_M   = 4'b0110;
    localparam COMPOSE  = 4'b0111;
    localparam DONE     = 4'b1000;
    localparam PRE_Z2   = 4'b1001; 
    localparam PRE_M    = 4'b1010; 
    
    reg [3:0] state;

    reg [2*HALF_WIDTH+1:0] Z0, Z2, M;
    reg [2*WIDTH-1:0] Z;                    

    reg [HALF_WIDTH:0] mult_a, mult_b;        
    wire [2*(HALF_WIDTH+1)-1:0] mult_result_full;     

    generate
        if (USE_RECURSION) begin : recursive_mult
            reg  sub_start;
            wire sub_ready;
            
            // Recursive Karatsuba instance
            (* DONT_TOUCH = "TRUE" *) (* KEEP_HIERARCHY = "YES" *) karatsuba_multiplier #(
                .WIDTH(HALF_WIDTH+1),                    
                .RECURSION_DEPTH(RECURSION_DEPTH - 1)
            ) sub_multiplier (
                .clk(clk),
                .rst(rst),
                .start(sub_start),
                .ready(sub_ready),
                .A(mult_a),
                .B(mult_b),
                .result(mult_result_full),
                .prng_noise(~prng_noise[HALF_WIDTH:0])
            );
            
            assign ready  = (state == IDLE || state == DONE);
            assign result = Z;
                        
            always @(posedge clk) begin
                if (rst) begin
                    state     <= IDLE;
                    Z0        <= 0;
                    Z2        <= 0;
                    M         <= 0;
                    Z         <= 0;
                    sub_start <= 1'b0;
                end else begin 
                    case (state)
                        IDLE: begin
                            if (start && ready) begin
                                mult_a    <= {1'b0, A[HALF_WIDTH-1:0]};
                                mult_b    <= {1'b0, B[HALF_WIDTH-1:0]};
                                sub_start <= 1'b1;
                                state     <= WAIT_Z0;
                            end
                        end
                        
                        WAIT_Z0: begin
                            sub_start <= 1'b0;
                            state     <= CALC_Z0;
                        end

                        CALC_Z0: begin
                            if (sub_ready) begin
                                Z0        <= {{2{1'b0}}, mult_result_full[2*HALF_WIDTH-1:0]};
                                mult_a    <= prng_noise[HALF_WIDTH:0];
                                mult_b    <= ~prng_noise[HALF_WIDTH:0];
                                sub_start <= 1'b0; 
                                state     <= PRE_Z2; 
                            end
                        end
                        
                        PRE_Z2: begin
                            mult_a    <= {1'b0, A[WIDTH-1:HALF_WIDTH]};
                            mult_b    <= {1'b0, B[WIDTH-1:HALF_WIDTH]};
                            sub_start <= 1'b1; 
                            state     <= WAIT_Z2;
                        end

                        WAIT_Z2: begin
                            sub_start <= 1'b0;
                            state     <= CALC_Z2;
                        end

                        CALC_Z2: begin
                            if (sub_ready) begin
                                Z2        <= {{2{1'b0}}, mult_result_full[2*HALF_WIDTH-1:0]};
                                mult_a    <= prng_noise[HALF_WIDTH:0];
                                mult_b    <= ~prng_noise[HALF_WIDTH:0];
                                sub_start <= 1'b0;
                                state     <= PRE_M;
                            end
                        end
                        
                        PRE_M: begin
                            mult_a    <= {1'b0, A[HALF_WIDTH-1:0]} + {1'b0, A[WIDTH-1:HALF_WIDTH]};
                            mult_b    <= {1'b0, B[HALF_WIDTH-1:0]} + {1'b0, B[WIDTH-1:HALF_WIDTH]};
                            sub_start <= 1'b1;
                            state     <= WAIT_M;
                        end
                        
                        WAIT_M: begin
                            sub_start <= 1'b0;
                            state     <= CALC_M;
                        end

                        CALC_M: begin
                            if (sub_ready) begin
                                M     <= mult_result_full[2*HALF_WIDTH+1:0];
                                state <= COMPOSE;
                            end
                        end

                        COMPOSE: begin
                            Z     <= ({Z2, {(2*HALF_WIDTH){1'b0}}}) + ({(M - Z0 - Z2), {HALF_WIDTH{1'b0}}}) + Z0;
                            state <= DONE;
                        end

                        DONE: begin
                            state <= IDLE;
                        end

                        default: state <= IDLE;
                    endcase
                end
            end
            
        end else begin : direct_mult            
            wire [2*HALF_WIDTH+1:0] mult_result_dsp;
            assign mult_result_dsp = mult_a * mult_b;
            assign ready        = (state == IDLE || state == DONE);
            assign result       = Z;
            
            always @(posedge clk) begin
                if (rst) begin
                    state <= IDLE;
                    Z0 <= 0; Z2 <= 0; M <= 0; Z <= 0;
                    mult_a <= 0; mult_b <= 0;
                end else begin
                    case (state)
                        IDLE: begin
                            if (start && ready) begin
                                mult_a <= {1'b0, A[HALF_WIDTH-1:0]};
                                mult_b <= {1'b0, B[HALF_WIDTH-1:0]};
                                state  <= CALC_Z0;
                            end
                        end
                        CALC_Z0: begin
                            Z0     <= mult_result_dsp; 
                            mult_a <= prng_noise[HALF_WIDTH:0];
                            mult_b <= ~prng_noise[HALF_WIDTH:0];
                            state  <= PRE_Z2;
                        end
                        
                        PRE_Z2: begin
                            mult_a <= {1'b0, A[WIDTH-1:HALF_WIDTH]};
                            mult_b <= {1'b0, B[WIDTH-1:HALF_WIDTH]};
                            state  <= CALC_Z2;
                        end

                        CALC_Z2: begin
                            Z2     <= mult_result_dsp; 
                            mult_a <= prng_noise[HALF_WIDTH:0];
                            mult_b <= ~prng_noise[HALF_WIDTH:0];
                            state  <= PRE_M;
                        end
                        
                        PRE_M: begin
                            mult_a <= {1'b0, A[HALF_WIDTH-1:0]} + {1'b0, A[WIDTH-1:HALF_WIDTH]};
                            mult_b <= {1'b0, B[HALF_WIDTH-1:0]} + {1'b0, B[WIDTH-1:HALF_WIDTH]};
                            state  <= CALC_M;
                        end

                        CALC_M: begin
                            M     <= mult_result_dsp; 
                            state <= COMPOSE;
                        end

                        COMPOSE: begin
                            Z     <= ({Z2, {(2*HALF_WIDTH){1'b0}}}) + ({(M - Z0 - Z2), {HALF_WIDTH{1'b0}}}) + Z0;
                            state <= DONE;
                        end

                        DONE: state <= IDLE;
                        default: state <= IDLE;
                    endcase
                end
            end
        end
    endgenerate

endmodule

(* KEEP_HIERARCHY = "YES" *) 
module poly1305_recombine_pipe (
    input  wire         clk,
    input  wire         rst,
    input  wire         en,        
    input  wire [133:0] in_a,       
    input  wire [133:0] in_b,
    input  wire [133:0] noise_1,
    input  wire [133:0] noise_2,
    input  wire [129:0] noise,      
    input  wire         sub_noise,  
    output reg  [130:0] result_share
);

    localparam [130:0] P = {1'b1, 130'b0} - 5;
    localparam [131:0] TWO_P = {1'b1, 130'b0, 1'b0} - 10; 

    // MUXING (Combinacional)
    (* KEEP = "TRUE" *) wire [133:0] op_a = en ? in_a : noise_1;
    (* KEEP = "TRUE" *) wire [133:0] op_b = en ? in_b : noise_2;
    (* KEEP = "TRUE" *) wire [129:0] op_noise_val = en ? noise : noise_1[129:0];
    (* KEEP = "TRUE" *) wire         op_sub_flag  = en ? sub_noise : noise_2[0];

    // --- STAGE 1 REGISTERS ---
    (* DONT_TOUCH = "TRUE" *) reg [134:0] st1_sum_ab; 
    (* DONT_TOUCH = "TRUE" *) reg [131:0] st1_noise_term;
    (* DONT_TOUCH = "TRUE" *) reg         st1_is_real;

    always @(posedge clk) begin
        if (rst) begin
            st1_sum_ab     <= 0;
            st1_noise_term <= 0;
            st1_is_real    <= 0;
        end else begin
            st1_sum_ab <= op_a + op_b;
            st1_noise_term <= op_sub_flag ? (TWO_P - {2'b0, op_noise_val}) : {2'b0, op_noise_val};
            st1_is_real <= en;
        end
    end

    // --- STAGE 2 COMBINATIONAL ---
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [135:0] total_sum_raw; 
    assign total_sum_raw = {1'b0, st1_sum_ab} + {4'b0, st1_noise_term};

    (* KEEP = "TRUE" *) wire [5:0]   upper_bits = total_sum_raw[135:130]; 
    (* KEEP = "TRUE" *) wire [129:0] lower_bits = total_sum_raw[129:0];   
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [8:0] upper_times_5;
    assign upper_times_5 = {upper_bits, 2'b00} + upper_bits;
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [130:0] sum_folded;
    assign sum_folded = lower_bits + upper_times_5;
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [130:0] diff_p;
    assign diff_p = sum_folded - P;
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire is_ge_p;
    assign is_ge_p = (sum_folded >= P);
    (* KEEP = "TRUE", DONT_TOUCH = "TRUE" *) wire [130:0] final_val;
    assign final_val = is_ge_p ? diff_p : sum_folded;

    // --- OUTPUT REGISTER ---
    always @(posedge clk) begin
        if (rst) begin
            result_share <= 0;
        end else if (st1_is_real) begin
            result_share <= final_val;
        end
    end

endmodule