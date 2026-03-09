`default_nettype none
// ChaCha20 cipher core with configurable pipeline stages and cipher rounds.

module chacha20_core #(
                        parameter integer PIPELINE_STAGES=20,// -- This number must be multiple of 2 and divisible by cc_rounds
                        parameter integer CIPHER_ROUNDS=20  // -- The number of rounds enters as a parameter to the module
                     )(                                     // -- i.e. for 20 rounds -> 2,4,10,20
                        input  wire         clk,            // -- Clock
                        input  wire         rst,            // -- Reset on low
                        input  wire [31:0]  init_ctr,       // -- Initial counter value
                        input  wire         next_ctr,       // -- Outputs next keystream for the next ctr value (already processed)
                        input  wire         cc_init,        // -- Begin computing rounds from the start values
                        input  wire         cc_next,        // -- Starts computing next blocks computation from the already saved values 
                        input  wire [255:0] key,            // -- Key
                        input  wire [95:0]  nonce,          // -- Nonce
                        output wire [511:0] keystream,      // -- Ciphertext message
                        output reg          valid_out,      // -- Valid out signal
                        output reg          ready           // -- Stall upstream when high
                      );
                   
      // Fixed constants and parameters
      localparam C0 = 32'h61707865;
      localparam C1 = 32'h3320646e;
      localparam C2 = 32'h79622d32;
      localparam C3 = 32'h6b206574;
      
      // Define FSM states
      localparam IDLE       = 3'b000;
      localparam COPY       = 3'b001;
      localparam NEXT       = 3'b010;
      localparam INCREMENT  = 3'b011;
      localparam NXT_INC    = 3'b100;
      localparam ROUNDS     = 3'b101;
      localparam OUT_RDY    = 3'b110;
      localparam OUT_NXT    = 3'b111;
      
      // Internal wires for chaining
      wire [31:0]   m [1:PIPELINE_STAGES][0:15];
      
      // Intermediate pipelined inputs to AU stages
      reg [31:0]    stage_input_regs [0:PIPELINE_STAGES-1][0:15];
      
      // Internal logic registers
      wire[511:0]   ks;
      reg [2:0]     state;
      reg [31:0]    m_initial [0:11];
      reg [5:0]     round_ctr, out_ctr;
      
      // Enable the qr functions when needed only 
      wire          enable_qrf;
      
      // Temporary loop variables 
      genvar i,j,c;
    
      // Generate depending on the PIPELINE_STAGES selected 
      generate
      for (i = 0; i < PIPELINE_STAGES; i = i + 1) begin : pipeline_gen    
        // Use registered inputs in AU
        chacha20_au #(.MODE(i % 2)) stage_inst (    .enable(enable_qrf), // This perform a fully round
          .m0(stage_input_regs[i][0]),  .m1(stage_input_regs[i][1]),
          .m2(stage_input_regs[i][2]),  .m3(stage_input_regs[i][3]),
          .m4(stage_input_regs[i][4]),  .m5(stage_input_regs[i][5]),
          .m6(stage_input_regs[i][6]),  .m7(stage_input_regs[i][7]),
          .m8(stage_input_regs[i][8]),  .m9(stage_input_regs[i][9]),
          .m10(stage_input_regs[i][10]),.m11(stage_input_regs[i][11]),
          .m12(stage_input_regs[i][12]),.m13(stage_input_regs[i][13]),
          .m14(stage_input_regs[i][14]),.m15(stage_input_regs[i][15]),
          .m0x(m[i+1][0]), .m1x(m[i+1][1]), .m2x(m[i+1][2]), .m3x(m[i+1][3]),
          .m4x(m[i+1][4]), .m5x(m[i+1][5]), .m6x(m[i+1][6]), .m7x(m[i+1][7]),
          .m8x(m[i+1][8]), .m9x(m[i+1][9]), .m10x(m[i+1][10]), .m11x(m[i+1][11]),
          .m12x(m[i+1][12]), .m13x(m[i+1][13]), .m14x(m[i+1][14]), .m15x(m[i+1][15])
        );
      end
      endgenerate
      
       //-- Enable QRF operations on selected states
       assign enable_qrf =  (state == COPY      || 
                             state == NEXT      || 
                             state == INCREMENT || 
                             state == NXT_INC   || 
                             state == ROUNDS    || 
                             state == OUT_NXT) ? 1'b1 : 1'b0;
      
      // Create the output keystream properly concatenated
      assign keystream = {
                ks[7:0],     ks[15:8],    ks[23:16],   ks[31:24],
                ks[39:32],   ks[47:40],   ks[55:48],   ks[63:56],
                ks[71:64],   ks[79:72],   ks[87:80],   ks[95:88],
                ks[103:96],  ks[111:104], ks[119:112], ks[127:120],
                ks[135:128], ks[143:136], ks[151:144], ks[159:152],
                ks[167:160], ks[175:168], ks[183:176], ks[191:184],
                ks[199:192], ks[207:200], ks[215:208], ks[223:216],
                ks[231:224], ks[239:232], ks[247:240], ks[255:248],
                ks[263:256], ks[271:264], ks[279:272], ks[287:280],
                ks[295:288], ks[303:296], ks[311:304], ks[319:312],
                ks[327:320], ks[335:328], ks[343:336], ks[351:344],
                ks[359:352], ks[367:360], ks[375:368], ks[383:376],
                ks[391:384], ks[399:392], ks[407:400], ks[415:408],
                ks[423:416], ks[431:424], ks[439:432], ks[447:440],
                ks[455:448], ks[463:456], ks[471:464], ks[479:472],
                ks[487:480], ks[495:488], ks[503:496], ks[511:504]
            };
     
      // Sequential part for each register      
      // Pipelined registers 1 to 2*pp ctrl
      generate
      for (i = 1; i < PIPELINE_STAGES; i = i + 1) begin : pipe_i
        for (j = 0; j < 16; j = j + 1) begin : pipe_j
          always @(posedge clk) begin
            if (rst) begin
              stage_input_regs[i][j] <= 32'b0;
            end else if (state == INCREMENT || state == ROUNDS || state == NXT_INC) begin
              stage_input_regs[i][j] <= m[i][j];
            end else begin
              stage_input_regs[i][j] <= stage_input_regs[i][j];
            end
          end
        end
      end
    endgenerate
    
    // Initial load
    // BEGIN and ROUNDS state init for stage_input_regs[0][j]
    always @(posedge clk) begin
        if (rst) begin 
            stage_input_regs[0][0]  <= 32'b0;
            stage_input_regs[0][1]  <= 32'b0;
            stage_input_regs[0][2]  <= 32'b0;
            stage_input_regs[0][3]  <= 32'b0;
            stage_input_regs[0][4]  <= 32'b0;
            stage_input_regs[0][5]  <= 32'b0;
            stage_input_regs[0][6]  <= 32'b0;
            stage_input_regs[0][7]  <= 32'b0;
            stage_input_regs[0][8]  <= 32'b0;
            stage_input_regs[0][9]  <= 32'b0;
            stage_input_regs[0][10] <= 32'b0;
            stage_input_regs[0][11] <= 32'b0;
            stage_input_regs[0][12] <= 32'b0;
            stage_input_regs[0][13] <= 32'b0;
            stage_input_regs[0][14] <= 32'b0;
            stage_input_regs[0][15] <= 32'b0;
        end else if (state == COPY || state == INCREMENT || state == NEXT || state == NXT_INC) begin
            // Static assignments for these 4 states
            stage_input_regs[0][0]  <= C0;
            stage_input_regs[0][1]  <= C1;
            stage_input_regs[0][2]  <= C2;
            stage_input_regs[0][3]  <= C3;
            stage_input_regs[0][4]  <= {key[231:224], key[239:232], key[247:240], key[255:248]};
            stage_input_regs[0][5]  <= {key[199:192], key[207:200], key[215:208], key[223:216]};
            stage_input_regs[0][6]  <= {key[167:160], key[175:168], key[183:176], key[191:184]};
            stage_input_regs[0][7]  <= {key[135:128], key[143:136], key[151:144], key[159:152]};
            stage_input_regs[0][8]  <= {key[103:96],  key[111:104], key[119:112], key[127:120]};
            stage_input_regs[0][9]  <= {key[71:64],   key[79:72],   key[87:80],   key[95:88]};
            stage_input_regs[0][10] <= {key[39:32],   key[47:40],   key[55:48],   key[63:56]};
            stage_input_regs[0][11] <= {key[7:0],     key[15:8],    key[23:16],   key[31:24]};
            stage_input_regs[0][13] <= {nonce[71:64], nonce[79:72], nonce[87:80], nonce[95:88]};
            stage_input_regs[0][14] <= {nonce[39:32], nonce[47:40], nonce[55:48], nonce[63:56]};
            stage_input_regs[0][15] <= {nonce[7:0],   nonce[15:8],  nonce[23:16],  nonce[31:24]};
        
            // Dynamic assignment for the counter based on specific state
            if (state == COPY) 
                stage_input_regs[0][12] <= init_ctr;
            else if (state == INCREMENT) 
                stage_input_regs[0][12] <= init_ctr + round_ctr;
            else if (state == NEXT) 
                stage_input_regs[0][12] <= m_initial[8] + PIPELINE_STAGES;
            else // NXT_INC
                stage_input_regs[0][12] <= m_initial[8] + round_ctr;
        end else if (state == ROUNDS || state == OUT_NXT) begin
            stage_input_regs[0][0]  <= m[PIPELINE_STAGES][0];
            stage_input_regs[0][1]  <= m[PIPELINE_STAGES][1];
            stage_input_regs[0][2]  <= m[PIPELINE_STAGES][2];
            stage_input_regs[0][3]  <= m[PIPELINE_STAGES][3];
            stage_input_regs[0][4]  <= m[PIPELINE_STAGES][4];
            stage_input_regs[0][5]  <= m[PIPELINE_STAGES][5];
            stage_input_regs[0][6]  <= m[PIPELINE_STAGES][6];
            stage_input_regs[0][7]  <= m[PIPELINE_STAGES][7];
            stage_input_regs[0][8]  <= m[PIPELINE_STAGES][8];
            stage_input_regs[0][9]  <= m[PIPELINE_STAGES][9];
            stage_input_regs[0][10] <= m[PIPELINE_STAGES][10];
            stage_input_regs[0][11] <= m[PIPELINE_STAGES][11];
            stage_input_regs[0][12] <= m[PIPELINE_STAGES][12];
            stage_input_regs[0][13] <= m[PIPELINE_STAGES][13];
            stage_input_regs[0][14] <= m[PIPELINE_STAGES][14];
            stage_input_regs[0][15] <= m[PIPELINE_STAGES][15];
        end else begin
            stage_input_regs[0][0]  <= stage_input_regs[0][0];
            stage_input_regs[0][1]  <= stage_input_regs[0][1];
            stage_input_regs[0][2]  <= stage_input_regs[0][2];
            stage_input_regs[0][3]  <= stage_input_regs[0][3];
            stage_input_regs[0][4]  <= stage_input_regs[0][4];
            stage_input_regs[0][5]  <= stage_input_regs[0][5];
            stage_input_regs[0][6]  <= stage_input_regs[0][6];
            stage_input_regs[0][7]  <= stage_input_regs[0][7];
            stage_input_regs[0][8]  <= stage_input_regs[0][8];
            stage_input_regs[0][9]  <= stage_input_regs[0][9];
            stage_input_regs[0][10] <= stage_input_regs[0][10];
            stage_input_regs[0][11] <= stage_input_regs[0][11];
            stage_input_regs[0][12] <= stage_input_regs[0][12];
            stage_input_regs[0][13] <= stage_input_regs[0][13];
            stage_input_regs[0][14] <= stage_input_regs[0][14];
            stage_input_regs[0][15] <= stage_input_regs[0][15];
        end
    end
      
      // Cycle round counter
      always @(posedge clk) begin
          if (rst) begin
            round_ctr <= 5'b0;
          end else begin
            if      (state == IDLE)         round_ctr <= 5'b00000;
            else if (state == COPY)         round_ctr <= 5'b00001;
            else if (state == ROUNDS || state == OUT_NXT || state == INCREMENT || state == NXT_INC)  
                                            round_ctr <= round_ctr + 1;
            else                            round_ctr <= round_ctr;
          end
      end  
      
      // Output round counter
      always @(posedge clk) begin
          if (rst) begin
            out_ctr <= 5'b0;
          end else begin
            if      (state == OUT_NXT)                  out_ctr <= out_ctr + 1;
            else if (state == COPY || state == NEXT)   
                                                        out_ctr <= 5'b0;
            else                                        out_ctr <= out_ctr;
          end
      end      
      
      // Inital matrix management
      always @(posedge clk) begin
          if (rst) begin
            m_initial[0]  <= 32'b0;  m_initial[1]  <= 32'b0;  m_initial[2]   <= 32'b0;  m_initial[3]   <= 32'b0;
            m_initial[4]  <= 32'b0;  m_initial[5]  <= 32'b0;  m_initial[6]   <= 32'b0;  m_initial[7]   <= 32'b0;
            m_initial[8]  <= 32'b0;  m_initial[9]  <= 32'b0;  m_initial[10]  <= 32'b0;  m_initial[11]  <= 32'b0;
          end else begin
              if (state == COPY) begin   
                m_initial[0]  <= {key[231:224], key[239:232], key[247:240], key[255:248]};
                m_initial[1]  <= {key[199:192], key[207:200], key[215:208], key[223:216]};
                m_initial[2]  <= {key[167:160], key[175:168], key[183:176], key[191:184]};
                m_initial[3]  <= {key[135:128], key[143:136], key[151:144], key[159:152]};
                m_initial[4]  <= {key[103:96],  key[111:104], key[119:112], key[127:120]};
                m_initial[5]  <= {key[71:64],   key[79:72],   key[87:80],   key[95:88]};
                m_initial[6] <= {key[39:32],   key[47:40],   key[55:48],   key[63:56]};
                m_initial[7] <= {key[7:0],     key[15:8],    key[23:16],   key[31:24]};
                m_initial[8] <= init_ctr;
                m_initial[9] <= {nonce[71:64], nonce[79:72], nonce[87:80], nonce[95:88]};
                m_initial[10] <= {nonce[39:32], nonce[47:40], nonce[55:48], nonce[63:56]};
                m_initial[11] <= {nonce[7:0],   nonce[15:8],  nonce[23:16],  nonce[31:24]};
              end else if (state == NEXT) m_initial[8] <= m_initial[8] + PIPELINE_STAGES;      // Update the ctr only
              else                        m_initial[8] <= m_initial[8];
          end
      end
      
      // raw keystream combinational asignement
      assign ks[(32*0)+31 -: 32] = stage_input_regs[0][0] + C0;
      assign ks[(32*1)+31 -: 32] = stage_input_regs[0][1] + C1;
      assign ks[(32*2)+31 -: 32] = stage_input_regs[0][2] + C2;
      assign ks[(32*3)+31 -: 32] = stage_input_regs[0][3] + C3;
      
      generate
          // Handle words 4 through 11 (the Key)
          for (c = 4; c < 12; c = c + 1) begin
                // Subtract 4 from 'c' because m_initial[0] corresponds to word 4
                assign ks[(32*c)+31 -: 32] = (stage_input_regs[0][c] + m_initial[c-4]);
          end
      endgenerate
      
      // Reg 12 (counter) - m_initial[8] is the stored init_ctr
      assign ks[(32*12)+31 -: 32] = (stage_input_regs[0][12] + m_initial[8] + out_ctr);
      
      // Regs 13,14 & 15 (Nonce)
      assign ks[(32*13)+31 -: 32] = (stage_input_regs[0][13] + m_initial[9]);
      assign ks[(32*14)+31 -: 32] = (stage_input_regs[0][14] + m_initial[10]);
      assign ks[(32*15)+31 -: 32] = (stage_input_regs[0][15] + m_initial[11]);
           
      // FSM sequential
      always@(posedge clk) begin
        if (rst) begin
                                                                            state <= IDLE;
                                                                            ready <= 1'b0;
                                                                            valid_out <= 1'b0;
        end                                                                    
        else begin
            case(state)
                IDLE: begin
                    if (cc_init) begin                                          
                                                                            state <= COPY;    
                                                                            valid_out <= 1'b0;
                                                                            ready <= 1'b0; 
                    end
                    else if (cc_next) begin
                                                                            state <= NEXT; 
                                                                            valid_out <= 1'b0;
                                                                            ready <= 1'b0; 
                    end
                end
                NEXT: begin
                                                                            state <= NXT_INC;
                end
                COPY: begin
                                                                            state <= INCREMENT;
                end
                INCREMENT: begin
                    if (round_ctr == PIPELINE_STAGES - 1)                   state <= ROUNDS;                                                     
                end
                NXT_INC: begin
                    if (round_ctr == PIPELINE_STAGES - 1)                   state <= ROUNDS;                                                     
                end
                ROUNDS: begin
                    if (round_ctr < PIPELINE_STAGES - 1)                    state <= INCREMENT;
                    else if (round_ctr == CIPHER_ROUNDS)                    state <= OUT_RDY;
                end          
                OUT_RDY: begin
                    valid_out <= 1'b1;
                    if (next_ctr) begin
                                                                            state <= OUT_NXT;
                                                                            valid_out <= 1'b0;
                    end     
                end
                OUT_NXT: begin
                    if (round_ctr == (CIPHER_ROUNDS + PIPELINE_STAGES - 1)) begin
                                                                            state <= IDLE;
                                                                            valid_out <= 1'b1;
                                                                            ready <= 1'b1; 
                    end                                                        
                    else if (!next_ctr)                                     state <= OUT_RDY;
                end
            endcase
        end
      end                     
endmodule

module chacha20_au #(parameter MODE=0)  // DUAL MODE GENERATION
                  (
                    input  wire        enable,
                    input  wire [31:0] m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15,
                    output wire [31:0] m0x, m1x, m2x, m3x, m4x, m5x, m6x, m7x, m8x, m9x, m10x, m11x, m12x, m13x, m14x, m15x
                   );
      
      // Generate depending on the mode selected to instantiate the qrf 4 times       
      generate
        if(MODE == 0) begin // Columns rounds
            chacha_qr_comb qrf0 (   .enable(enable),
                .a_in(m0), .b_in(m4), .c_in(m8), .d_in(m12),
                .a_out(m0x), .b_out(m4x), .c_out(m8x), .d_out(m12x)
            );
            chacha_qr_comb qrf1 (   .enable(enable),
                .a_in(m1), .b_in(m5), .c_in(m9), .d_in(m13),
                .a_out(m1x), .b_out(m5x), .c_out(m9x), .d_out(m13x)
            );
            chacha_qr_comb qrf2 (   .enable(enable),
                .a_in(m2), .b_in(m6), .c_in(m10), .d_in(m14),
                .a_out(m2x), .b_out(m6x), .c_out(m10x), .d_out(m14x)
            );
            chacha_qr_comb qrf3 (   .enable(enable),
                .a_in(m3), .b_in(m7), .c_in(m11), .d_in(m15),
                .a_out(m3x), .b_out(m7x), .c_out(m11x), .d_out(m15x)
            );
        end else if (MODE == 1) begin      // Diagonal rounds
            chacha_qr_comb qrf0 (   .enable(enable),
                .a_in(m0), .b_in(m5), .c_in(m10), .d_in(m15),
                .a_out(m0x), .b_out(m5x), .c_out(m10x), .d_out(m15x)
            );
            chacha_qr_comb qrf1 (   .enable(enable),
                .a_in(m1), .b_in(m6), .c_in(m11), .d_in(m12),
                .a_out(m1x), .b_out(m6x), .c_out(m11x), .d_out(m12x)
            );
            chacha_qr_comb qrf2 (   .enable(enable),
                .a_in(m2), .b_in(m7), .c_in(m8), .d_in(m13),
                .a_out(m2x), .b_out(m7x), .c_out(m8x), .d_out(m13x)
            );
            chacha_qr_comb qrf3 (   .enable(enable),
                .a_in(m3), .b_in(m4), .c_in(m9), .d_in(m14),
                .a_out(m3x), .b_out(m4x), .c_out(m9x), .d_out(m14x)
            );
        end 
      endgenerate
      
endmodule
