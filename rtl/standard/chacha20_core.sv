// =============================================================================
// chacha20_core.sv
// Standard (Unprotected) ChaCha20 Core
// Configurable number of quarter-round units for throughput/area trade-off.
// =============================================================================

`timescale 1ns / 1ps

module chacha20_core #(
    parameter NUM_QR_UNITS = 4  // 1, 2, or 4 parallel QR units
)(
    input  logic         clk,
    input  logic         rst_n,

    // Control
    input  logic         start,
    output logic         busy,
    output logic         done,

    // Key, nonce, counter
    input  logic [255:0] key,
    input  logic [95:0]  nonce,
    input  logic [31:0]  counter,

    // Keystream output (512-bit block)
    output logic [511:0] keystream,
    output logic         keystream_valid
);

    // ChaCha20 state: 16 x 32-bit words
    logic [31:0] state     [0:15];
    logic [31:0] work_state[0:15];
    logic [31:0] init_state[0:15];

    // Round counter (20 rounds = 10 double-rounds)
    logic [3:0] round_cnt;

    // FSM states
    typedef enum logic [2:0] {
        IDLE,
        INIT,
        COLUMN_ROUND,
        DIAGONAL_ROUND,
        FINALIZE
    } state_t;

    state_t fsm_state, fsm_next;

    // ChaCha20 constants: "expand 32-byte k"
    localparam logic [31:0] SIGMA0 = 32'h61707865;
    localparam logic [31:0] SIGMA1 = 32'h3320646e;
    localparam logic [31:0] SIGMA2 = 32'h79622d32;
    localparam logic [31:0] SIGMA3 = 32'h6b206574;

    // QR unit I/O
    logic [31:0] qr_a_in  [0:NUM_QR_UNITS-1];
    logic [31:0] qr_b_in  [0:NUM_QR_UNITS-1];
    logic [31:0] qr_c_in  [0:NUM_QR_UNITS-1];
    logic [31:0] qr_d_in  [0:NUM_QR_UNITS-1];
    logic [31:0] qr_a_out [0:NUM_QR_UNITS-1];
    logic [31:0] qr_b_out [0:NUM_QR_UNITS-1];
    logic [31:0] qr_c_out [0:NUM_QR_UNITS-1];
    logic [31:0] qr_d_out [0:NUM_QR_UNITS-1];
    logic        qr_en    [0:NUM_QR_UNITS-1];
    logic        qr_valid [0:NUM_QR_UNITS-1];

    // Instantiate QR units
    genvar gi;
    generate
        for (gi = 0; gi < NUM_QR_UNITS; gi++) begin : gen_qr
            chacha20_qr u_qr (
                .clk   (clk),
                .rst_n (rst_n),
                .en    (qr_en[gi]),
                .a_in  (qr_a_in[gi]),
                .b_in  (qr_b_in[gi]),
                .c_in  (qr_c_in[gi]),
                .d_in  (qr_d_in[gi]),
                .a_out (qr_a_out[gi]),
                .b_out (qr_b_out[gi]),
                .c_out (qr_c_out[gi]),
                .d_out (qr_d_out[gi]),
                .valid (qr_valid[gi])
            );
        end
    endgenerate

    // FSM
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            fsm_state <= IDLE;
        else
            fsm_state <= fsm_next;
    end

    always_comb begin
        fsm_next = fsm_state;
        case (fsm_state)
            IDLE:
                if (start) fsm_next = INIT;
            INIT:
                fsm_next = COLUMN_ROUND;
            COLUMN_ROUND:
                if (qr_valid[0]) fsm_next = DIAGONAL_ROUND;
            DIAGONAL_ROUND:
                if (qr_valid[0]) begin
                    if (round_cnt == 4'd9)
                        fsm_next = FINALIZE;
                    else
                        fsm_next = COLUMN_ROUND;
                end
            FINALIZE:
                fsm_next = IDLE;
            default:
                fsm_next = IDLE;
        endcase
    end

    // Round counter
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            round_cnt <= 4'd0;
        else if (fsm_state == INIT)
            round_cnt <= 4'd0;
        else if (fsm_state == DIAGONAL_ROUND && qr_valid[0])
            round_cnt <= round_cnt + 4'd1;
    end

    // State initialization
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 16; i++) begin
                init_state[i] <= 32'd0;
                work_state[i] <= 32'd0;
            end
        end else if (fsm_state == INIT) begin
            // Initialize state matrix
            init_state[0]  <= SIGMA0;
            init_state[1]  <= SIGMA1;
            init_state[2]  <= SIGMA2;
            init_state[3]  <= SIGMA3;
            init_state[4]  <= key[31:0];
            init_state[5]  <= key[63:32];
            init_state[6]  <= key[95:64];
            init_state[7]  <= key[127:96];
            init_state[8]  <= key[159:128];
            init_state[9]  <= key[191:160];
            init_state[10] <= key[223:192];
            init_state[11] <= key[255:224];
            init_state[12] <= counter;
            init_state[13] <= nonce[31:0];
            init_state[14] <= nonce[63:32];
            init_state[15] <= nonce[95:64];

            work_state[0]  <= SIGMA0;
            work_state[1]  <= SIGMA1;
            work_state[2]  <= SIGMA2;
            work_state[3]  <= SIGMA3;
            work_state[4]  <= key[31:0];
            work_state[5]  <= key[63:32];
            work_state[6]  <= key[95:64];
            work_state[7]  <= key[127:96];
            work_state[8]  <= key[159:128];
            work_state[9]  <= key[191:160];
            work_state[10] <= key[223:192];
            work_state[11] <= key[255:224];
            work_state[12] <= counter;
            work_state[13] <= nonce[31:0];
            work_state[14] <= nonce[63:32];
            work_state[15] <= nonce[95:64];
        end
    end

    // Control and output signals
    assign busy           = (fsm_state != IDLE);
    assign done           = (fsm_state == FINALIZE);
    assign keystream_valid = (fsm_state == FINALIZE);

    // Finalize: state + initial_state
    always_comb begin
        for (int i = 0; i < 16; i++) begin
            state[i] = work_state[i] + init_state[i];
        end
    end

    // Pack keystream output
    generate
        for (gi = 0; gi < 16; gi++) begin : gen_ks
            assign keystream[gi*32 +: 32] = state[gi];
        end
    endgenerate

endmodule
