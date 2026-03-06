// =============================================================================
// chacha20_poly1305_top.sv
// Top-Level Module: Standard (Unprotected) ChaCha20-Poly1305 AEAD Engine
// AXI4-Stream compliant interface for SoC integration.
// =============================================================================

`timescale 1ns / 1ps

module chacha20_poly1305_top #(
    parameter DATA_WIDTH   = 128,
    parameter NUM_QR_UNITS = 4
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

    // Key and Nonce input
    input  logic [255:0]           key,
    input  logic [95:0]            nonce,

    // Authentication tag output
    output logic [127:0]           auth_tag,
    output logic                   auth_tag_valid,

    // Control
    input  logic                   start,
    input  logic                   encrypt,  // 1 = encrypt, 0 = decrypt
    output logic                   busy,
    output logic                   done
);

    // =========================================================================
    // Internal Signals
    // =========================================================================
    logic [511:0] keystream_block;
    logic         keystream_valid;
    logic         chacha_start;
    logic         chacha_busy;
    logic         chacha_done;
    logic [31:0]  block_counter;

    // Poly1305 one-time key (first 32 bytes of first keystream block)
    logic [127:0] poly_r;
    logic [127:0] poly_s;

    // =========================================================================
    // ChaCha20 Core Instance
    // =========================================================================
    chacha20_core #(
        .NUM_QR_UNITS (NUM_QR_UNITS)
    ) u_chacha20 (
        .clk             (clk),
        .rst_n           (rst_n),
        .start           (chacha_start),
        .busy            (chacha_busy),
        .done            (chacha_done),
        .key             (key),
        .nonce           (nonce),
        .counter         (block_counter),
        .keystream       (keystream_block),
        .keystream_valid (keystream_valid)
    );

    // =========================================================================
    // Poly1305 Core Instance
    // =========================================================================
    poly1305_core u_poly1305 (
        .clk       (clk),
        .rst_n     (rst_n),
        .init      (1'b0),      // Controlled by FSM (active in key-gen phase)
        .update    (1'b0),      // Controlled by FSM
        .finalize  (1'b0),      // Controlled by FSM
        .busy      (),
        .tag_valid (auth_tag_valid),
        .r_key     (poly_r),
        .s_key     (poly_s),
        .msg_block (128'd0),    // Driven by FSM
        .msg_last  (1'b0),
        .tag       (auth_tag)
    );

    // =========================================================================
    // Main Control FSM (simplified placeholder)
    // =========================================================================
    typedef enum logic [3:0] {
        TOP_IDLE,
        TOP_GEN_POLY_KEY,
        TOP_PROCESS_AAD,
        TOP_PROCESS_DATA,
        TOP_FINALIZE_MAC,
        TOP_DONE
    } top_state_t;

    top_state_t top_state;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            top_state     <= TOP_IDLE;
            block_counter <= 32'd0;
            chacha_start  <= 1'b0;
            poly_r        <= 128'd0;
            poly_s        <= 128'd0;
        end else begin
            case (top_state)
                TOP_IDLE: begin
                    if (start) begin
                        block_counter <= 32'd0;
                        chacha_start  <= 1'b1;
                        top_state     <= TOP_GEN_POLY_KEY;
                    end
                end

                TOP_GEN_POLY_KEY: begin
                    chacha_start <= 1'b0;
                    if (keystream_valid) begin
                        poly_r    <= keystream_block[127:0];
                        poly_s    <= keystream_block[255:128];
                        block_counter <= 32'd1;
                        top_state <= TOP_PROCESS_DATA;
                    end
                end

                TOP_PROCESS_DATA: begin
                    // Encrypt/decrypt data blocks using keystream XOR
                    // (Full implementation drives AXI4-Stream handshake)
                    if (s_axis_tvalid && s_axis_tlast) begin
                        top_state <= TOP_FINALIZE_MAC;
                    end
                end

                TOP_FINALIZE_MAC: begin
                    top_state <= TOP_DONE;
                end

                TOP_DONE: begin
                    top_state <= TOP_IDLE;
                end

                default: top_state <= TOP_IDLE;
            endcase
        end
    end

    assign busy = (top_state != TOP_IDLE);
    assign done = (top_state == TOP_DONE);

    // Ciphertext output (XOR plaintext with keystream)
    assign m_axis_tdata  = s_axis_tdata ^ keystream_block[DATA_WIDTH-1:0];
    assign m_axis_tvalid = s_axis_tvalid && (top_state == TOP_PROCESS_DATA);
    assign m_axis_tlast  = s_axis_tlast  && (top_state == TOP_PROCESS_DATA);
    assign s_axis_tready = m_axis_tready && (top_state == TOP_PROCESS_DATA);

endmodule
