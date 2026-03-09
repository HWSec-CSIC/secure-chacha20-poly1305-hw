`default_nettype none
// Kogge-Stone Adder optimized for 1st-order TI (3-share masking)
// per Schneider et al.

// Parametric KSA module for N bits (1st-order masking)
(* KEEP_HIERARCHY = "YES" *)
module ksa_ti_3 #(
    parameter N_BITS = 32
)(
    input  wire              clk,
    input  wire              rst,
    input  wire              run,
    input  wire [N_BITS-1:0] rand_bits, 
    input  wire [N_BITS-1:0] a_in_1, a_in_2, a_in_3, 
    input  wire [N_BITS-1:0] b_in_1, b_in_2, b_in_3, 
    output wire [N_BITS-1:0] s_out_1, s_out_2, s_out_3 
);

    localparam N_STAGES = $clog2(N_BITS); 
    
    // Pipeline Registers
    reg [N_BITS-1:0] g [0:N_STAGES][0:2]; 
    reg [N_BITS-1:0] p [0:N_STAGES][0:2];

    // Intermediate wires
    wire [N_BITS-1:0] g_next [0:N_STAGES][0:2]; 
    wire [N_BITS-1:0] p_next [0:N_STAGES][0:2];
    
    genvar k, s, i;

    assign p_next[0][0] = a_in_1 ^ b_in_1;
    assign p_next[0][1] = a_in_2 ^ b_in_2;
    assign p_next[0][2] = a_in_3 ^ b_in_3;
    
    // Update random value when run==True AND not stalled
    reg [N_BITS-1:0] rand_bits_reg;     
    always@(posedge clk) begin
        if(rst)          rand_bits_reg <= 0;
        else if (run) rand_bits_reg <= rand_bits; 
    end
    
    generate
        for (k = 0; k < N_BITS; k = k + 1) begin : prep_g
            (* KEEP_HIERARCHY = "YES" *) ti_and_remask_3share u_and_g (
                .a1(a_in_1[k]), .a2(a_in_2[k]), .a3(a_in_3[k]),
                .b1(b_in_1[k]), .b2(b_in_2[k]), .b3(b_in_3[k]),
                .m(rand_bits_reg[k]), 
                .q1(g_next[0][0][k]), .q2(g_next[0][1][k]), .q3(g_next[0][2][k])
            );
        end
    endgenerate

    generate
        for (s = 0; s < N_STAGES; s = s + 1) begin : ksa_stages
            localparam integer SHIFT = (1 << s);
            
            for (i = 0; i < N_BITS; i = i + 1) begin : bits
                if (i < SHIFT) begin
                    // Buffer
                    assign g_next[s+1][0][i] = g[s][0][i];
                    assign g_next[s+1][1][i] = g[s][1][i];
                    assign g_next[s+1][2][i] = g[s][2][i];
                    
                    assign p_next[s+1][0][i] = p[s][0][i];
                    assign p_next[s+1][1][i] = p[s][1][i];
                    assign p_next[s+1][2][i] = p[s][2][i];
                end else begin

                    // G_new (TI Group Logic Standardized)
                    (* KEEP_HIERARCHY = "YES" *) ti_group_g_3share_std u_group_g (
                        .gi1(g[s][0][i]),       .gi2(g[s][1][i]),       .gi3(g[s][2][i]),
                        .gj1(g[s][0][i-SHIFT]), .gj2(g[s][1][i-SHIFT]), .gj3(g[s][2][i-SHIFT]),
                        .pi1(p[s][0][i]),       .pi2(p[s][1][i]),       .pi3(p[s][2][i]),
                        .qo1(g_next[s+1][0][i]),.qo2(g_next[s+1][1][i]),.qo3(g_next[s+1][2][i])
                    );

                    // P_new (TI AND with mask reuse)
                    (* KEEP_HIERARCHY = "YES" *) ti_and_remask_3share u_group_p (
                        .a1(p[s][0][i]),        .a2(p[s][1][i]),        .a3(p[s][2][i]),
                        .b1(p[s][0][i-SHIFT]), .b2(p[s][1][i-SHIFT]), .b3(p[s][2][i-SHIFT]),
                        .m(g[s][0][i-SHIFT]),  
                        .q1(p_next[s+1][0][i]),.q2(p_next[s+1][1][i]),.q3(p_next[s+1][2][i])
                    );
                end
            end
        end
    endgenerate

    reg [N_BITS-1:0] p_delay [0:N_STAGES][0:2];
    integer j, m_idx;

    always @(posedge clk) begin
        if (rst) begin
            // Full Reset
            for (j = 0; j <= N_STAGES; j = j + 1) begin
                for (m_idx = 0; m_idx < 3; m_idx = m_idx + 1) begin
                    g[j][m_idx] <= 0;
                    p[j][m_idx] <= 0;
                    p_delay[j][m_idx] <= 0; 
                end
            end
        end else if (run) begin 
        
            for (m_idx = 0; m_idx < 3; m_idx = m_idx + 1) begin
                g[0][m_idx] <= g_next[0][m_idx];
                p[0][m_idx] <= p_next[0][m_idx];
            end
            for (j = 0; j < N_STAGES; j = j + 1) begin
                for (m_idx = 0; m_idx < 3; m_idx = m_idx + 1) begin
                    g[j+1][m_idx] <= g_next[j+1][m_idx];
                    p[j+1][m_idx] <= p_next[j+1][m_idx];
                end
            end

            p_delay[0][0] <= p_next[0][0]; 
            p_delay[0][1] <= p_next[0][1]; 
            p_delay[0][2] <= p_next[0][2];
            
            for (j = 0; j < N_STAGES; j = j + 1) begin
                p_delay[j+1][0] <= p_delay[j][0];
                p_delay[j+1][1] <= p_delay[j][1];
                p_delay[j+1][2] <= p_delay[j][2];
            end
        end
    end

    wire [N_BITS-1:0] c_final_1, c_final_2, c_final_3;
    
    // C = G shifted left by 1
    assign c_final_1 = {g[N_STAGES][0][N_BITS-2:0], 1'b0};
    assign c_final_2 = {g[N_STAGES][1][N_BITS-2:0], 1'b0};
    assign c_final_3 = {g[N_STAGES][2][N_BITS-2:0], 1'b0};

    // S = P_delayed ^ C
    assign s_out_1 = p_delay[N_STAGES][0] ^ c_final_1;
    assign s_out_2 = p_delay[N_STAGES][1] ^ c_final_2;
    assign s_out_3 = p_delay[N_STAGES][2] ^ c_final_3;

endmodule

(* KEEP_HIERARCHY = "YES" *)
module ti_and_remask_3share (
    input  wire a1, a2, a3,
    input  wire b1, b2, b3,
    input  wire m,          
    output wire q1, q2, q3
);
    assign q1 = (a2 & b2) ^ (a2 & b3) ^ (a3 & b2) ^ m;
    assign q2 = (a3 & b3) ^ (a1 & b3) ^ (a3 & b1) ^ (a1 & m) ^ (b1 & m);
    assign q3 = (a1 & b1) ^ (a1 & b2) ^ (a2 & b1) ^ (a1 & m) ^ (b1 & m) ^ m;
endmodule

(* KEEP_HIERARCHY = "YES" *)
module ti_group_g_3share_std (
    input  wire gi1, gi2, gi3, 
    input  wire gj1, gj2, gj3, 
    input  wire pi1, pi2, pi3, 
    output wire qo1, qo2, qo3
);

    assign qo1 = gi1 ^ (gj2 & pi2) ^ (gj2 & pi3) ^ (gj3 & pi2);
    assign qo2 = gi2 ^ (gj3 & pi3) ^ (gj3 & pi1) ^ (gj1 & pi3);
    assign qo3 = gi3 ^ (gj1 & pi1) ^ (gj1 & pi2) ^ (gj2 & pi1);

endmodule