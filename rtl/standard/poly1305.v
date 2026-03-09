`default_nettype none
// Poly1305 MAC engine with Karatsuba multiplier and modular reduction.

module poly1305_core#(
           parameter RECURSION_DEPTH = 2
    )(
    input  wire         clk,
    input  wire         rst,
    input  wire         start,      // -- Begins MAC calculation from given key
    input  wire         next,       // -- Adds next msg block to the MAC accumulator
    input  wire         finish,     // -- Last msg block introduced, compute the MAC value
    input  wire [127:0] msg,        // -- Message to calculate MAC
    input  wire [4:0]   valid_bytes,// -- Needed for the padding thing
    input  wire [255:0] key,        // .. Key used during MAC 
    output reg  [127:0] mac,        // -- Valid MAC value         
    output reg          valid_out,  // -- Valid out signal
    output wire         ready       // -- Stall upstream when high
);
    // Define FSM states
    localparam IDLE     = 4'b0000;
    localparam START    = 4'b0001;
    localparam ADD_PAD  = 4'b0010;
    localparam ADD_SUM  = 4'b0011;
    localparam ADD_SUB  = 4'b0100;
    localparam ADD_COMP = 4'b0101;
    localparam ST_MUL   = 4'b0110;
    localparam END_MUL  = 4'b0111;
    localparam ADD_END  = 4'b1000; 
    localparam END      = 4'b1001; 
    
    // Poly1305 constant
    localparam [130:0] P = {1'b1, 130'b0} - 5; 
    
    // Clamp mask
    localparam [127:0] CLAMP_MASK = 128'h0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF; 
    
    // Define internal registers to be used
    reg [130:0] acc;
    reg [129:0] n_blk;
    reg [127:0] r_side, s_side;
    reg [3:0]   state;
    
    // Internal wires
    wire [129:0] r_expanded, a_mul, mac_sum, acc_sub;
    wire  mul_st, mul_rdy;
    
    // Instantiate multiplier and reduction block
    poly1305_mul_mod_opt #(
        .RECURSION_DEPTH(RECURSION_DEPTH)
    ) mul_mod_module (
        .clk(clk),
        .rst(rst),
        .start(mul_st),
        .A(r_expanded),
        .B(acc[129:0]),    
        .Zrw(a_mul),
        .ready(mul_rdy)
    );
    
    // Combinational 
    assign r_expanded = {2'b00, r_side};    
    assign mac_sum = s_side + acc;
    assign acc_sub = acc - P;
    assign mul_st = (state == ST_MUL);
    
    //n_blk seq. assignement    
    always @(posedge clk) begin
        if (rst)    
            n_blk <= 0;                             
        else if (state == IDLE && next) begin            
            n_blk <= {
                2'b00,                                                                  // Construct padding
                msg[7:0],    msg[15:8],    msg[23:16],   msg[31:24],    
                msg[39:32],  msg[47:40],   msg[55:48],   msg[63:56],    
                msg[71:64],  msg[79:72],   msg[87:80],   msg[95:88],    
                msg[103:96], msg[111:104], msg[119:112], msg[127:120]   
            }; 
            if (!valid_bytes)   n_blk[128]                    <= 1'b1;    
            else                n_blk[(valid_bytes * 8) +: 8] <= 8'h01;                      
        end else
            n_blk <= n_blk;                     
    end 
    
    // R and S sides logic
    always @(posedge clk) begin
        if (rst) begin
            r_side <= 128'b0;
            s_side <= 128'b0;
        end else if (state == START) begin
            r_side <= {
                key[135:128], key[143:136], key[151:144], key[159:152],  
                key[167:160], key[175:168], key[183:176], key[191:184],  
                key[199:192], key[207:200], key[215:208], key[223:216],  
                key[231:224], key[239:232], key[247:240], key[255:248]   
            } & CLAMP_MASK;
            s_side <= {
                key[7:0],     key[15:8],    key[23:16],   key[31:24],    
                key[39:32],   key[47:40],   key[55:48],   key[63:56],    
                key[71:64],   key[79:72],   key[87:80],   key[95:88],    
                key[103:96],  key[111:104], key[119:112], key[127:120]   
            };
        end else begin
            r_side <= r_side;
            s_side <= s_side;
        end
    end

    // Accumulator logic
    always @(posedge clk) begin
        if (rst || state == START)                  acc <= 130'b0;
        else if (state == ADD_SUM)                  acc <= acc + n_blk;
        else if (state == ADD_COMP) begin
            if (acc > P)                            acc <= acc_sub;
            else                                    acc <= acc;
        end 
        else if (state == ADD_END)                  acc <= a_mul;
        else                                        acc <= acc;
    end  
    
    // valid_out logic
    always @(posedge clk) begin
        if      (rst)                               valid_out <= 1'b0;
        else if (state == START)                    valid_out <= 1'b0;
        else if (state == END)                      valid_out <= 1'b1;
        else                                        valid_out <= valid_out;
    end 
    
    // mac logic
    always @(posedge clk) begin
        if  (rst)                         
            mac <= 128'b0;
        else if (state == END)  begin
            mac <= {
                mac_sum[7:0],    mac_sum[15:8],    mac_sum[23:16],   mac_sum[31:24],   
                mac_sum[39:32],  mac_sum[47:40],   mac_sum[55:48],   mac_sum[63:56],    
                mac_sum[71:64],  mac_sum[79:72],   mac_sum[87:80],   mac_sum[95:88],    
                mac_sum[103:96], mac_sum[111:104], mac_sum[119:112], mac_sum[127:120]   
            };
        end else
            mac <= mac;
    end
    
    // Combiational Handshake is perfect
    assign ready = (state == IDLE);

    // FSM sequential
    always@(posedge clk) begin
        if (rst)                                        state <= IDLE;
        else begin
            case(state)
                IDLE: begin
                    if (start)                          state <= START;     
                    else if (next)                      state <= ADD_PAD;
                    else if (finish)                    state <= END;
                end
                START: begin
                    if (!start)                         state <= IDLE;
                end
                ADD_PAD: begin
                                                        state <= ADD_SUM;
                end
                ADD_SUM: begin
                                                        state <= ADD_SUB;
                end
                ADD_SUB: begin
                                                        state <= ADD_COMP;
                end
                ADD_COMP: begin
                                                        state <= ST_MUL;
                end
                ST_MUL: begin
                                                        state <= END_MUL; 
                end
                END_MUL: begin
                    if (mul_rdy)                        state <= ADD_END;
                end
                ADD_END: begin
                    if (!next)                          state <= IDLE;
                end  
                END: begin
                    if (!finish)                        state <= IDLE;
                end
            endcase
        end
      end        
endmodule


module poly1305_mul_mod_opt #(
    parameter RECURSION_DEPTH = 1
)(  
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    output wire         ready,
    input  wire [129:0] A,
    input  wire [129:0] B,
    output wire [129:0] Zrw
);
    // Poly1305 constant P = 2^130 - 5
    localparam [130:0] P = {1'b1, 130'b0} - 5;
    
    // FSM States
    localparam IDLE     = 3'b000;
    localparam ST_MUL   = 3'b001;
    localparam END_MUL  = 3'b010;
    localparam REDUCE_1 = 3'b011;
    localparam REDUCE_2 = 3'b100;
    localparam REDUCE_3 = 3'b101; 
    localparam DONE     = 3'b110; 
    
    reg [2:0] state;
    reg [129:0] Zr;
    
    // Karatsuba multiplier signals
    reg mult_start;
    wire mult_ready;
    wire [259:0] mult_result;
    
    karatsuba_multiplier #(
        .WIDTH(130),
        .RECURSION_DEPTH(RECURSION_DEPTH)
    ) karatsuba_mult (
        .clk(clk), .rst(rst), .start(mult_start), .ready(mult_ready),
        .A(A), .B(B), .result(mult_result)
    );
    
    reg  [132:0] raw_sum;        
    reg  [130:0] folded_sum;     
    wire [130:0] final_result;   
    
    wire [132:0] calc_raw_sum = (mult_result[259:130] << 2) + mult_result[259:130] + mult_result[129:0];
    wire [130:0] calc_folded_sum = raw_sum[129:0] + (raw_sum[132:130] * 3'd5);

    assign final_result = (folded_sum >= P) ? (folded_sum - P) : folded_sum;
    assign Zrw = Zr;
    assign ready = (state == IDLE || state == DONE);
    
    always @(posedge clk) begin
        if (rst) begin
            state      <= IDLE;
            mult_start <= 1'b0;
            Zr         <= 0;
            raw_sum    <= 0;
            folded_sum <= 0;
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
                    state <= END_MUL;
                end
                
                END_MUL: begin
                    if (mult_ready) begin
                        state <= REDUCE_1;
                    end
                end

                REDUCE_1: begin
                    raw_sum <= calc_raw_sum;
                    state   <= REDUCE_2;
                end
                
                REDUCE_2: begin
                    folded_sum <= calc_folded_sum;
                    state      <= REDUCE_3;        
                end

                REDUCE_3: begin
                    Zr    <= final_result[129:0]; 
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

// Karatsuba multiplier
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
    output wire [2*WIDTH-1:0] result
);

    localparam HALF_WIDTH = (WIDTH + 1) >> 1;
    
    localparam USE_RECURSION = (RECURSION_DEPTH > 0) && (WIDTH > 16);
    
    // FSM States
    localparam IDLE     = 4'b0000;
    localparam WAIT_Z0  = 4'b0001;
    localparam CALC_Z0  = 4'b0010;
    localparam WAIT_Z2  = 4'b0011;
    localparam CALC_Z2  = 4'b0100;
    localparam WAIT_M   = 4'b0101;
    localparam CALC_M   = 4'b0110;
    localparam COMPOSE  = 4'b0111;
    localparam DONE     = 4'b1000;
    
    reg [3:0] state;

    // Intermediate values                      
    reg [2*HALF_WIDTH+1:0] Z0, Z2, M;
    reg [2*WIDTH-1:0] Z;                    

    // Shared multiplier signals 
    reg [HALF_WIDTH:0] mult_a, mult_b;        
    wire [2*(HALF_WIDTH+1)-1:0] mult_result_full;     

    generate
        if (USE_RECURSION) begin : recursive_mult
            reg sub_start;
            wire sub_ready;
            
            // Recursive Karatsuba instance
            karatsuba_multiplier #(
                .WIDTH(HALF_WIDTH+1),                    
                .RECURSION_DEPTH(RECURSION_DEPTH - 1)
            ) sub_multiplier (
                .clk(clk),
                .rst(rst),
                .start(sub_start),
                .ready(sub_ready),
                .A(mult_a),
                .B(mult_b),
                .result(mult_result_full)
            );
            
            assign ready = (state == IDLE || state == DONE);
            assign result = Z;
                        
            // FSM with proper handshaking for recursive case
            always @(posedge clk) begin
                if (rst) begin
                    state      <= IDLE;
                    Z0         <= 0;
                    Z2         <= 0;
                    M          <= 0;
                    Z          <= 0;
                    sub_start  <= 1'b0;
                end else begin
                    case (state)
                        IDLE: begin
                            if (start && ready) begin
                                mult_a <= {1'b0, A[HALF_WIDTH-1:0]};
                                mult_b <= {1'b0, B[HALF_WIDTH-1:0]};
                                sub_start <= 1'b1;
                                state    <= WAIT_Z0;
                            end
                        end
                        
                        WAIT_Z0: begin
                            sub_start <= 1'b0;
                            state    <= CALC_Z0;
                        end

                        CALC_Z0: begin
                            if (sub_ready) begin
                                Z0       <= {{2{1'b0}}, mult_result_full[2*HALF_WIDTH-1:0]};
                                mult_a  <= {1'b0, A[WIDTH-1:HALF_WIDTH]};
                                mult_b  <= {1'b0, B[WIDTH-1:HALF_WIDTH]};
                                sub_start <= 1'b1;
                                state    <= WAIT_Z2;
                            end
                        end
                        
                        WAIT_Z2: begin
                            sub_start <= 1'b0;
                            state    <= CALC_Z2;
                        end

                        CALC_Z2: begin
                            if (sub_ready) begin
                                Z2       <= {{2{1'b0}}, mult_result_full[2*HALF_WIDTH-1:0]};
                                mult_a  <= {1'b0, A[HALF_WIDTH-1:0]} + {1'b0, A[WIDTH-1:HALF_WIDTH]};
                                mult_b  <= {1'b0, B[HALF_WIDTH-1:0]} + {1'b0, B[WIDTH-1:HALF_WIDTH]};
                                sub_start <= 1'b1;
                                state    <= WAIT_M;
                            end
                        end
                        
                        WAIT_M: begin
                            sub_start <= 1'b0;
                            state    <= CALC_M;
                        end

                        CALC_M: begin
                            if (sub_ready) begin
                                M      <= mult_result_full[2*HALF_WIDTH+1:0];
                                state  <= COMPOSE;
                            end
                        end

                        COMPOSE: begin
                            Z <= ({Z2, {(2*HALF_WIDTH){1'b0}}}) + ({(M - Z0 - Z2), {HALF_WIDTH{1'b0}}}) + Z0;
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
            wire [2*HALF_WIDTH+1:0] mult_result;
            assign mult_result = mult_a * mult_b;
            assign ready       = (state == IDLE || state == DONE);
            assign result      = Z;
            
            always @(posedge clk) begin
                if (rst) begin
                    state <= IDLE;
                    Z0    <= 0;
                    Z2    <= 0;
                    M     <= 0;
                    Z     <= 0;
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
                            Z0      <= mult_result; 
                            mult_a  <= {1'b0, A[WIDTH-1:HALF_WIDTH]};
                            mult_b  <= {1'b0, B[WIDTH-1:HALF_WIDTH]};
                            state   <= CALC_Z2;
                        end

                        CALC_Z2: begin
                            Z2      <= mult_result; 
                            mult_a  <= {1'b0, A[HALF_WIDTH-1:0]} + {1'b0, A[WIDTH-1:HALF_WIDTH]};
                            mult_b  <= {1'b0, B[HALF_WIDTH-1:0]} + {1'b0, B[WIDTH-1:HALF_WIDTH]};
                            state   <= CALC_M;
                        end

                        CALC_M: begin
                            M      <= mult_result; 
                            state  <= COMPOSE;
                        end

                        COMPOSE: begin
                            Z <= ({Z2, {(2*HALF_WIDTH){1'b0}}}) + ({(M - Z0 - Z2), {HALF_WIDTH{1'b0}}}) + Z0;
                            state <= DONE;
                        end

                        DONE: begin
                            state <= IDLE;
                        end

                        default: state <= IDLE;
                    endcase
                end
            end
        end
    endgenerate

endmodule
