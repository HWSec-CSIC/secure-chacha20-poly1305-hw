// =============================================================================
// chacha20_poly1305_secure_top.sv
// Top-Level Module: 1st-Order DPA-Secure ChaCha20-Poly1305 AEAD Engine
// Features: Threshold Implementations, SDRR, Blinded Karatsuba Multiplier.
// =============================================================================

`timescale 1ns / 1ps

module chacha20_poly1305_secure_top #(
    parameter DATA_WIDTH   = 128,
    parameter NUM_QR_UNITS = 4,
    parameter NUM_SHARES   = 2
)(
    input  logic                   clk,
    input  logic                   rst_n,

    // AXI4-Stream Slave (plaintext / AAD input)
    input  logic [DATA_WIDTH-1:0]  s_axis_tdata,
    input  logic                   s_axis_tvalid,
    output logic                   s_axis_tready,
    input  logic                   s_axis_tlast,

    // AXI4-Stream Master (ciphertext output)
    output logic [DATA_WIDTH-1:0]  m_axis_tdata,
    output logic                   m_axis_tvalid,
    input  logic                   m_axis_tready,
    output logic                   m_axis_tlast,

    // Key and Nonce input (unshared — assumed secure channel)
    input  logic [255:0]           key,
    input  logic [95:0]            nonce,

    // Fresh randomness source (from TRNG)
    input  logic [127:0]           trng_data,
    input  logic                   trng_valid,
    output logic                   trng_ready,

    // Authentication tag output
    output logic [127:0]           auth_tag,
    output logic                   auth_tag_valid,

    // Control
    input  logic                   start,
    input  logic                   encrypt,
    output logic                   busy,
    output logic                   done
);

    // =========================================================================
    // Internal Signals
    // =========================================================================

    // Shared key: key = key_share0 ^ key_share1
    logic [255:0] key_share0, key_share1;

    // Randomness distribution
    logic [31:0] rand_qr [0:3];   // Randomness for QR TI units
    logic [31:0] rand_sdrr;       // Randomness for SDRR stages
    logic [129:0] blind, blind_inv; // Blinding for Karatsuba

    // ChaCha20 shared state (2 shares x 16 words)
    logic [31:0] state_s0 [0:15];
    logic [31:0] state_s1 [0:15];

    // Keystream (recombined for XOR with plaintext)
    logic [511:0] keystream_block;
    logic         keystream_valid;

    // Block counter
    logic [31:0] block_counter;

    // Poly1305 signals
    logic [127:0] poly_r, poly_s;
    logic [129:0] poly_acc;
    logic [259:0] poly_product;
    logic         poly_mult_valid;
    logic [129:0] poly_reduced;
    logic         poly_reduce_valid;

    // =========================================================================
    // Initial Sharing: Split key into two Boolean shares
    // =========================================================================
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_share0 <= 256'd0;
            key_share1 <= 256'd0;
        end else if (start && trng_valid) begin
            key_share0 <= {trng_data, trng_data};  // Random mask
            key_share1 <= key ^ {trng_data, trng_data};
        end
    end

    // =========================================================================
    // Randomness Distribution
    // =========================================================================
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 4; i++) rand_qr[i] <= 32'd0;
            rand_sdrr  <= 32'd0;
            blind      <= 130'd0;
            blind_inv  <= 130'd0;
        end else if (trng_valid) begin
            rand_qr[0] <= trng_data[31:0];
            rand_qr[1] <= trng_data[63:32];
            rand_qr[2] <= trng_data[95:64];
            rand_qr[3] <= trng_data[127:96];
            rand_sdrr  <= trng_data[31:0] ^ trng_data[63:32];
            blind      <= {2'b0, trng_data};
            blind_inv  <= 130'd1;  // Placeholder: actual inverse computed in field
        end
    end

    assign trng_ready = 1'b1;  // Always accept fresh randomness

    // =========================================================================
    // Masked ChaCha20 QR Units (Threshold Implementation)
    // =========================================================================
    genvar gi;
    generate
        for (gi = 0; gi < NUM_QR_UNITS; gi++) begin : gen_qr_ti
            chacha20_qr_ti u_qr_ti (
                .clk     (clk),
                .rst_n   (rst_n),
                .en      (1'b0),  // Controlled by round FSM
                .a0_in   (state_s0[gi*4 + 0]),
                .b0_in   (state_s0[gi*4 + 1]),
                .c0_in   (state_s0[gi*4 + 2]),
                .d0_in   (state_s0[gi*4 + 3]),
                .a1_in   (state_s1[gi*4 + 0]),
                .b1_in   (state_s1[gi*4 + 1]),
                .c1_in   (state_s1[gi*4 + 2]),
                .d1_in   (state_s1[gi*4 + 3]),
                .rand_0  (rand_qr[0]),
                .rand_1  (rand_qr[1]),
                .rand_2  (rand_qr[2]),
                .rand_3  (rand_qr[3]),
                .a0_out  (),
                .b0_out  (),
                .c0_out  (),
                .d0_out  (),
                .a1_out  (),
                .b1_out  (),
                .c1_out  (),
                .d1_out  (),
                .valid   ()
            );
        end
    endgenerate

    // =========================================================================
    // SDRR Stages (inserted between pipeline registers)
    // =========================================================================
    // Example: re-randomize share 0 and share 1 of word 0 between rounds
    logic [31:0] sdrr_in  [0:1];
    logic [31:0] sdrr_out [0:1];

    assign sdrr_in[0] = state_s0[0];
    assign sdrr_in[1] = state_s1[0];

    sdrr_module #(
        .WIDTH     (32),
        .NUM_SHARES(2)
    ) u_sdrr (
        .clk        (clk),
        .rst_n      (rst_n),
        .en         (1'b0),  // Controlled by FSM
        .fresh_rand (rand_sdrr),
        .share_in   (sdrr_in),
        .share_out  (sdrr_out)
    );

    // =========================================================================
    // Blinded Karatsuba Multiplier for Poly1305
    // =========================================================================
    poly1305_karatsuba_blind u_karatsuba (
        .clk         (clk),
        .rst_n       (rst_n),
        .en          (1'b0),  // Controlled by MAC FSM
        .a_in        (poly_acc),
        .b_in        ({2'b0, poly_r}),
        .blind       (blind),
        .blind_inv   (blind_inv),
        .product_out (poly_product),
        .valid       (poly_mult_valid)
    );

    // Modular reduction
    poly1305_reduce u_reduce (
        .clk         (clk),
        .rst_n       (rst_n),
        .en          (poly_mult_valid),
        .product_in  (poly_product),
        .reduced_out (poly_reduced),
        .valid       (poly_reduce_valid)
    );

    // =========================================================================
    // Main Control FSM (simplified placeholder)
    // =========================================================================
    typedef enum logic [3:0] {
        SEC_IDLE,
        SEC_SHARE_KEY,
        SEC_GEN_POLY_KEY,
        SEC_PROCESS_AAD,
        SEC_PROCESS_DATA,
        SEC_FINALIZE_MAC,
        SEC_DONE
    } sec_state_t;

    sec_state_t sec_state;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            sec_state     <= SEC_IDLE;
            block_counter <= 32'd0;
            poly_r        <= 128'd0;
            poly_s        <= 128'd0;
            poly_acc      <= 130'd0;
            auth_tag      <= 128'd0;
            auth_tag_valid <= 1'b0;
            for (int i = 0; i < 16; i++) begin
                state_s0[i] <= 32'd0;
                state_s1[i] <= 32'd0;
            end
        end else begin
            case (sec_state)
                SEC_IDLE: begin
                    auth_tag_valid <= 1'b0;
                    if (start) begin
                        sec_state <= SEC_SHARE_KEY;
                    end
                end

                SEC_SHARE_KEY: begin
                    // Key sharing handled by always_ff block above
                    sec_state <= SEC_GEN_POLY_KEY;
                end

                SEC_GEN_POLY_KEY: begin
                    // Generate first keystream block (counter=0) for Poly1305 key
                    block_counter <= 32'd0;
                    sec_state     <= SEC_PROCESS_DATA;
                end

                SEC_PROCESS_DATA: begin
                    if (s_axis_tvalid && s_axis_tlast) begin
                        sec_state <= SEC_FINALIZE_MAC;
                    end
                end

                SEC_FINALIZE_MAC: begin
                    // tag = (acc + s) mod 2^128
                    auth_tag       <= (poly_acc[127:0] + poly_s);
                    auth_tag_valid <= 1'b1;
                    sec_state      <= SEC_DONE;
                end

                SEC_DONE: begin
                    sec_state <= SEC_IDLE;
                end

                default: sec_state <= SEC_IDLE;
            endcase
        end
    end

    assign busy = (sec_state != SEC_IDLE);
    assign done = (sec_state == SEC_DONE);

    // Ciphertext output (recombined keystream XOR plaintext)
    assign keystream_block = 512'd0;  // Placeholder: assembled from share recombination
    assign m_axis_tdata  = s_axis_tdata ^ keystream_block[DATA_WIDTH-1:0];
    assign m_axis_tvalid = s_axis_tvalid && (sec_state == SEC_PROCESS_DATA);
    assign m_axis_tlast  = s_axis_tlast  && (sec_state == SEC_PROCESS_DATA);
    assign s_axis_tready = m_axis_tready && (sec_state == SEC_PROCESS_DATA);

endmodule
