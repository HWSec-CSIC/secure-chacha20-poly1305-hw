// =============================================================================
// poly1305_core.sv
// Standard (Unprotected) Poly1305 MAC Core
// Fully unrolled Karatsuba multiplier for field multiplication mod 2^130-5.
// =============================================================================

`timescale 1ns / 1ps

module poly1305_core (
    input  logic         clk,
    input  logic         rst_n,

    // Control
    input  logic         init,
    input  logic         update,
    input  logic         finalize,
    output logic         busy,
    output logic         tag_valid,

    // One-time key pair (r, s) derived from keystream
    input  logic [127:0] r_key,   // Clamped 'r' value
    input  logic [127:0] s_key,   // 's' value

    // Message block (128-bit chunks)
    input  logic [127:0] msg_block,
    input  logic         msg_last,

    // Output tag
    output logic [127:0] tag
);

    // Accumulator
    logic [129:0] acc;

    // Clamped r
    logic [129:0] r_clamped;

    // Padded message block
    logic [129:0] msg_padded;

    // Product from multiplier
    logic [259:0] product;

    // Reduced result
    logic [129:0] reduced;
    logic         reduce_valid;

    // Clamp r according to RFC 8439 spec
    function automatic [127:0] clamp(input [127:0] r);
        clamp = r;
        clamp[3:0]   = 4'b0;
        clamp[7:4]   = r[7:4];
        clamp[35:32] = 4'b0;
        clamp[39:36] = r[39:36];
        clamp[67:64] = 4'b0;
        clamp[71:68] = r[71:68];
        clamp[99:96] = 4'b0;
        clamp[103:100] = r[103:100];
        // Also clear top bits of each 4-byte limb
        clamp[31:28] &= 4'b1111;
        clamp[63:60] &= 4'b1100;
        clamp[95:92] &= 4'b1111;
        clamp[127:124] &= 4'b1100;
    endfunction

    // FSM
    typedef enum logic [2:0] {
        S_IDLE,
        S_INIT,
        S_ACCUMULATE,
        S_MULTIPLY,
        S_REDUCE,
        S_FINALIZE
    } state_t;

    state_t fsm_state, fsm_next;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            fsm_state <= S_IDLE;
        else
            fsm_state <= fsm_next;
    end

    always_comb begin
        fsm_next = fsm_state;
        case (fsm_state)
            S_IDLE: begin
                if (init)     fsm_next = S_INIT;
                if (update)   fsm_next = S_ACCUMULATE;
                if (finalize) fsm_next = S_FINALIZE;
            end
            S_INIT:       fsm_next = S_IDLE;
            S_ACCUMULATE: fsm_next = S_MULTIPLY;
            S_MULTIPLY:   fsm_next = S_REDUCE;
            S_REDUCE:     if (reduce_valid) fsm_next = S_IDLE;
            S_FINALIZE:   fsm_next = S_IDLE;
            default:      fsm_next = S_IDLE;
        endcase
    end

    // Accumulator logic
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            acc       <= 130'd0;
            r_clamped <= 130'd0;
        end else begin
            case (fsm_state)
                S_INIT: begin
                    acc       <= 130'd0;
                    r_clamped <= {2'b0, clamp(r_key)};
                end
                S_ACCUMULATE: begin
                    // Pad message: append 0x01 byte
                    msg_padded = {1'b1, 1'b0, msg_block};
                    acc <= acc + msg_padded;
                end
                S_REDUCE: begin
                    if (reduce_valid)
                        acc <= reduced;
                end
                default: ;
            endcase
        end
    end

    // Karatsuba multiplier: acc * r_clamped
    // Full 260-bit product
    assign product = acc * r_clamped;

    // Modular reduction
    poly1305_reduce u_reduce (
        .clk         (clk),
        .rst_n       (rst_n),
        .en          (fsm_state == S_MULTIPLY),
        .product_in  (product),
        .reduced_out (reduced),
        .valid       (reduce_valid)
    );

    // Finalize: tag = (acc + s) mod 2^128
    logic [130:0] tag_sum;
    assign tag_sum = acc + {2'b0, s_key};

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tag       <= 128'd0;
            tag_valid <= 1'b0;
        end else if (fsm_state == S_FINALIZE) begin
            tag       <= tag_sum[127:0];
            tag_valid <= 1'b1;
        end else begin
            tag_valid <= 1'b0;
        end
    end

    assign busy = (fsm_state != S_IDLE);

endmodule
