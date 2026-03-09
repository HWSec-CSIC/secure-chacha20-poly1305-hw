`default_nettype none
// AEAD core top controller — orchestrates ChaCha20 keystream, Poly1305 MAC,
// ciphertext generation and tag computation per RFC 8439.

module aead_core_top #(
    parameter integer PIPELINE_STAGES = 4,
    parameter integer CIPHER_ROUNDS   = 20,
    parameter integer RECURSION_DEPTH = 1
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
    output reg  [511:0]  ciphertext,
    output reg  [127:0]  tag,
    output reg  [1:0]    valid,
    output reg           ready,
    output reg           busy,
    output reg  [12:0]   busy_cnt 
);

    localparam NO_OP        = 2'b00;
    localparam AAD_NEXT     = 2'b01;  
    localparam PT_NEXT      = 2'b10;
    localparam AEAD_END     = 2'b11;

    localparam NONE         = 2'b00;
    localparam VALID_CT     = 2'b01;
    localparam VALID_MAC    = 2'b10;

    localparam ctr_initial  = 32'd0;
    
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
    localparam GET_CT       = 5'h0B;
    localparam ADD_PT_BLK0  = 5'h0C;
    localparam WT_PT_BLK0   = 5'h0D;
    localparam ADD_PT_BLK1  = 5'h0E;
    localparam WT_PT_BLK1   = 5'h0F;
    localparam ADD_PT_BLK2  = 5'h10;
    localparam WT_PT_BLK2   = 5'h11;    
    localparam ADD_PT_BLK3  = 5'h12;
    localparam WT_PT_BLK3   = 5'h13;
    localparam ADD_CTRS_END = 5'h14;
    localparam WT_CTRS_END  = 5'h15;
    localparam FINISH_MAC   = 5'h16;
    localparam WAIT_MAC     = 5'h17;

    // Wires
    wire [511:0] keystream;
    wire         cc_valid, cc_ready, poly_done, poly_ready;
    wire [127:0] poly_mac;
    wire [511:0] data_src;

    // Regs
    reg  [255:0] poly_key;
    reg  [127:0] poly_msg;
    reg          cc_init, cc_next_ctr, cc_next;
    reg          poly_start, poly_next, poly_finish;
    reg  [4:0]   state;
    reg          nxt_sect; 
    reg  [63:0]  aad_len_reg, pt_len_reg;
    reg  [63:0]  aad_len_ctr, pt_len_ctr;   
    reg          start_d, start_edg;
    
    // Phase Register: 0=Calculate New, 1=Use Buffer
    reg          ks_phase;

    // Functions
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

    // Combinational part
    assign data_src = enc ? ciphertext : plaintext;

    // Instances
    chacha20_core #(
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
        .keystream(keystream),
        .valid_out(cc_valid),
        .ready(cc_ready)
    );

    poly1305_core #(
        .RECURSION_DEPTH(RECURSION_DEPTH)
    ) poly_inst (
        .clk(clk), .rst(rst),
        .start(poly_start),
        .next(poly_next),
        .finish(poly_finish),
        .msg(poly_msg),
        .valid_bytes(5'd0), 
        .key(poly_key),
        .mac(poly_mac),
        .valid_out(poly_done),
        .ready(poly_ready)
    );
    
    // SEQUENTIAL LOGIC
    
    // Tag storage
    always @(posedge clk) begin
        if (rst)    tag <= 128'b0;
        else if (state == WAIT_MAC && poly_done)
                    tag <= poly_mac;
    end
    
    // Length Counters
    always @(posedge clk) begin
        if (rst) begin
            aad_len_reg  <= 64'b0;
            aad_len_ctr  <= 64'b0;
            pt_len_reg   <= 64'b0; pt_len_ctr   <= 64'b0;
        end else if (state == START_PKEY) begin
            aad_len_ctr  <= {32'b0, aad_len};
            aad_len_reg  <= {32'b0, aad_len};
            pt_len_ctr   <= {32'b0, pt_len};  pt_len_reg   <= {32'b0, pt_len};
        end else if (state == SUM_AAD) begin 
            if (aad_len_ctr < 64'd64)   aad_len_ctr  <= 64'd0;
            else                        aad_len_ctr  <= aad_len_ctr - 64'd64;
        end else if ((state == WT_PT_BLK0 || state == WT_PT_BLK1 || state == WT_PT_BLK2 || state == WT_PT_BLK3) && !poly_ready) begin 
            if (pt_len_ctr < 64'd16) pt_len_ctr <= 64'd0;
            else                     pt_len_ctr <= pt_len_ctr - 64'd16;
        end
    end 
    
    // Edge detection
    always @(posedge clk) begin
        if (rst) begin start_d <= 1'b0; start_edg <= 1'b0; end 
        else begin start_edg <= start & ~start_d; start_d <= start; end
    end
    
    // Ciphertext
    always @(posedge clk) begin
        if (rst) ciphertext <= 512'b0;
        else if (state == GET_CT) ciphertext <= plaintext ^ keystream;
    end       

    // Valid Signal
    always @(posedge clk) begin
      if (rst) valid <= NONE;
      else begin
          valid <= NONE;
          if (state == GET_CT) valid <= VALID_CT;
          else if (state == WAIT_MAC && poly_done) valid <= VALID_MAC;
      end
    end 
        
    // Poly Key Logic
    always @(posedge clk) begin
      if (rst) begin
          poly_key <= 256'b0;
      end else if (state == GET_PKEY && cc_valid) begin
          poly_key <= keystream[511:256]; 
      end else if (state == WAIT_MAC && poly_done) begin
          poly_key <= 256'b0; 
      end
    end
    
    // Poly Message Logic
    always @(posedge clk) begin
        if (rst) poly_msg <= 128'b0;
        else case (state)
            ADD_AAD, WAIT_AAD: poly_msg <= aad & le_byte_mask(aad_len_ctr[5:0]);
            
            ADD_PT_BLK0: poly_msg <= data_src[511:384] & le_byte_mask((pt_len_ctr >= 16) ? 6'd16 : pt_len_ctr[5:0]);
            ADD_PT_BLK1: poly_msg <= data_src[383:256] & le_byte_mask((pt_len_ctr >= 16) ? 6'd16 : pt_len_ctr[5:0]);
            ADD_PT_BLK2: poly_msg <= data_src[255:128] & le_byte_mask((pt_len_ctr >= 16) ? 6'd16 : pt_len_ctr[5:0]);
            ADD_PT_BLK3: poly_msg <= data_src[127:0]   & le_byte_mask((pt_len_ctr >= 16) ? 6'd16 : pt_len_ctr[5:0]);
            
            ADD_CTRS_END: poly_msg <= {
                aad_len_reg[7:0],   aad_len_reg[15:8],   aad_len_reg[23:16],  aad_len_reg[31:24],
                aad_len_reg[39:32], aad_len_reg[47:40],  aad_len_reg[55:48],  aad_len_reg[63:56],
                pt_len_reg[7:0],    pt_len_reg[15:8],    pt_len_reg[23:16],   pt_len_reg[31:24],
                pt_len_reg[39:32],  pt_len_reg[47:40],   pt_len_reg[55:48],   pt_len_reg[63:56]
            };
        endcase
    end
    
    // MAIN FSM
    always @(posedge clk) begin
        if (rst) begin
            cc_init <= 0;
            cc_next_ctr <= 0; cc_next <= 0;
            poly_start <= 0; poly_next <= 0; poly_finish <= 0;
            ready <= 0;
            nxt_sect <= 0;
            state <= IDLE;
            ks_phase <= 1'b0; 
            busy <= 1'b0;
        end else begin
            cc_init <= 0;
            cc_next_ctr <= 0; cc_next <= 0;
            poly_start <= 0; poly_next <= 0; poly_finish <= 0;
            ready <= 0;
            case (state)
                IDLE: begin 
                    ready <= 1'b1;
                    if (start_edg && next_blk == 0 && poly_key == 0) begin   
                        cc_init     <= 1'b1;
                        ks_phase    <= 1'b1; 
                        state       <= START_PKEY; 
                        nxt_sect    <= (aad_len == 0);
                        busy        <= 1'b1;
                    end 
                    else if ((start_edg && next_blk == AAD_NEXT) || (aad_len_ctr > 64'd0 && poly_key != 0)) begin 
                        state       <= ADD_AAD;
                    end 
                    else if (start_edg && next_blk == PT_NEXT) begin   
                        if (ks_phase == 1'b0) begin
                            cc_next  <= 1'b1;
                            ks_phase <= 1'b1;
                        end else begin
                            cc_next_ctr <= 1'b1;
                            ks_phase    <= 1'b0;
                        end
                        state <= WAIT_KS_ACK;
                    end 
                    else if ((start_edg && next_blk == AEAD_END) || (aad_len_ctr == 32'd0 && pt_len_ctr == 32'b0 && poly_key != 0)) begin
                        state <= ADD_CTRS_END;
                    end                     
                end
                
                START_PKEY: begin state <= WAIT_KS_ACK; end
                WAIT_KS_ACK: begin if (!cc_valid) state <= WAIT_VALID_K; end
                WAIT_VALID_K: begin if (cc_valid) state <= (poly_key == 0) ? GET_PKEY : GET_CT; end
                WAIT_PKEY:  begin if(cc_valid) state <= GET_PKEY; end 
                GET_PKEY:   begin state <= START_MAC; end
                START_MAC:  begin poly_start <= 1'b1; if(!poly_ready) state <= WAIT_ST_MAC; end
                
                WAIT_ST_MAC: begin
                    if (poly_ready) begin
                        if (!nxt_sect) state <= ADD_AAD;
                        else begin
                            cc_next_ctr <= 1'b1;
                            ks_phase    <= 1'b0; 
                            state       <= WAIT_KS_ACK;
                        end
                    end
                end
                
                ADD_AAD: begin if (poly_ready) begin poly_next <= 1; state <= SUM_AAD; end end
                SUM_AAD: state <= WAIT_AAD;
                
                WAIT_AAD: begin
                    if (poly_ready) begin
                        if (pt_len_ctr > 0) begin
                            cc_next_ctr <= 1'b1;
                            ks_phase    <= 1'b0;
                            state       <= WAIT_KS_ACK;
                        end else begin
                            state <= IDLE;
                        end
                    end
                end
                
                GET_CT: state <= ADD_PT_BLK0;
                
                ADD_PT_BLK0: if (poly_ready) begin 
                    poly_next <= 1; 
                    state <= (pt_len_ctr==0)? IDLE : WT_PT_BLK0;
                end
                WT_PT_BLK0: begin 
                    if (!poly_ready) begin
                        if (pt_len_ctr <= 64'd16) state <= IDLE;
                        else                      state <= ADD_PT_BLK1;
                    end
                end
                
                ADD_PT_BLK1: if (poly_ready) begin 
                    poly_next <= 1; 
                    state <= (pt_len_ctr==0)? IDLE : WT_PT_BLK1;
                end
                WT_PT_BLK1: begin
                    if (!poly_ready) begin
                        if (pt_len_ctr <= 64'd16) state <= IDLE;
                        else                      state <= ADD_PT_BLK2;
                    end
                end
                
                ADD_PT_BLK2: if (poly_ready) begin 
                    poly_next <= 1; 
                    state <= (pt_len_ctr==0)? IDLE : WT_PT_BLK2;
                end
                WT_PT_BLK2: begin
                    if (!poly_ready) begin
                        if (pt_len_ctr <= 64'd16) state <= IDLE;
                        else                      state <= ADD_PT_BLK3;
                    end
                end
                
                ADD_PT_BLK3:  if (poly_ready) begin poly_next <= 1; state <= WT_PT_BLK3; end
                WT_PT_BLK3:   if (!poly_ready) state <= IDLE;
                ADD_CTRS_END: if (poly_ready) begin poly_next <= 1; state <= WT_CTRS_END; end
                WT_CTRS_END:  if (!poly_ready) state <= FINISH_MAC;
                FINISH_MAC:   if (poly_ready) begin poly_finish <= 1; state <= WAIT_MAC; end
                WAIT_MAC:     if (poly_done)  begin state <= IDLE;    busy <= 1'b0;  end
                
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