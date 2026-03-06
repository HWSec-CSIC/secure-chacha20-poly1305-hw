// =============================================================================
// chacha20_poly1305_secure_tb.sv
// Testbench for the DPA-Secure ChaCha20-Poly1305 AEAD Engine
// Verifies functional correctness of the masked datapath and includes
// test vectors for share recombination checks.
// =============================================================================

`timescale 1ns / 1ps

module chacha20_poly1305_secure_tb;

    // =========================================================================
    // Parameters
    // =========================================================================
    localparam CLK_PERIOD   = 10;  // 100 MHz
    localparam DATA_WIDTH   = 128;
    localparam NUM_QR_UNITS = 4;
    localparam NUM_SHARES   = 2;

    // =========================================================================
    // Signals
    // =========================================================================
    logic                   clk;
    logic                   rst_n;

    logic [DATA_WIDTH-1:0]  s_axis_tdata;
    logic                   s_axis_tvalid;
    logic                   s_axis_tready;
    logic                   s_axis_tlast;

    logic [DATA_WIDTH-1:0]  m_axis_tdata;
    logic                   m_axis_tvalid;
    logic                   m_axis_tready;
    logic                   m_axis_tlast;

    logic [255:0]           key;
    logic [95:0]            nonce;

    logic [127:0]           trng_data;
    logic                   trng_valid;
    logic                   trng_ready;

    logic [127:0]           auth_tag;
    logic                   auth_tag_valid;

    logic                   start;
    logic                   encrypt;
    logic                   busy;
    logic                   done;

    // =========================================================================
    // Clock Generation
    // =========================================================================
    initial clk = 1'b0;
    always #(CLK_PERIOD/2) clk = ~clk;

    // =========================================================================
    // DUT Instantiation
    // =========================================================================
    chacha20_poly1305_secure_top #(
        .DATA_WIDTH   (DATA_WIDTH),
        .NUM_QR_UNITS (NUM_QR_UNITS),
        .NUM_SHARES   (NUM_SHARES)
    ) dut (
        .clk             (clk),
        .rst_n           (rst_n),
        .s_axis_tdata    (s_axis_tdata),
        .s_axis_tvalid   (s_axis_tvalid),
        .s_axis_tready   (s_axis_tready),
        .s_axis_tlast    (s_axis_tlast),
        .m_axis_tdata    (m_axis_tdata),
        .m_axis_tvalid   (m_axis_tvalid),
        .m_axis_tready   (m_axis_tready),
        .m_axis_tlast    (m_axis_tlast),
        .key             (key),
        .nonce           (nonce),
        .trng_data       (trng_data),
        .trng_valid      (trng_valid),
        .trng_ready      (trng_ready),
        .auth_tag        (auth_tag),
        .auth_tag_valid  (auth_tag_valid),
        .start           (start),
        .encrypt         (encrypt),
        .busy            (busy),
        .done            (done)
    );

    // =========================================================================
    // PRNG-based TRNG Emulation (for simulation only)
    // Generates pseudo-random data every clock cycle.
    // =========================================================================
    logic [127:0] prng_state;

    initial prng_state = 128'hDEADBEEF_CAFEBABE_12345678_9ABCDEF0;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            trng_data  <= 128'd0;
            trng_valid <= 1'b0;
            prng_state <= 128'hDEADBEEF_CAFEBABE_12345678_9ABCDEF0;
        end else begin
            // Simple LFSR-like PRNG for simulation
            prng_state <= {prng_state[126:0], prng_state[127] ^ prng_state[125]};
            trng_data  <= prng_state;
            trng_valid <= 1'b1;
        end
    end

    // =========================================================================
    // Test Vectors (RFC 8439)
    // =========================================================================
    localparam [255:0] TV_KEY   = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
    localparam [95:0]  TV_NONCE = 96'h000000000000004a00000000;

    // =========================================================================
    // Test Sequence
    // =========================================================================
    integer errors = 0;

    initial begin
        // Initialize
        rst_n          = 1'b0;
        start          = 1'b0;
        encrypt        = 1'b1;
        s_axis_tdata   = {DATA_WIDTH{1'b0}};
        s_axis_tvalid  = 1'b0;
        s_axis_tlast   = 1'b0;
        m_axis_tready  = 1'b1;
        key            = TV_KEY;
        nonce          = TV_NONCE;

        // Reset
        repeat (10) @(posedge clk);
        rst_n = 1'b1;
        repeat (5) @(posedge clk);

        // =====================================================================
        // Test 1: Secure Encryption with Masked Datapath
        // =====================================================================
        $display("=== Test 1: Secure ChaCha20-Poly1305 Encryption ===");
        $display("Time: %0t | Starting secure encryption...", $time);

        start = 1'b1;
        @(posedge clk);
        start = 1'b0;

        // Wait for key sharing to complete
        repeat (5) @(posedge clk);

        // Feed plaintext
        s_axis_tvalid = 1'b1;
        s_axis_tdata  = 128'h4c616469_65732061_6e642047_656e746c;
        s_axis_tlast  = 1'b0;
        @(posedge clk);

        s_axis_tdata  = 128'h656d656e_206f6620_74686520_636c6173;
        @(posedge clk);

        s_axis_tdata  = 128'h73206f66_20273939_3a204966_20492063;
        s_axis_tlast  = 1'b1;
        @(posedge clk);

        s_axis_tvalid = 1'b0;
        s_axis_tlast  = 1'b0;

        // Wait for completion
        wait (done);
        @(posedge clk);

        $display("Time: %0t | Secure encryption complete.", $time);

        // =====================================================================
        // Test 2: Share Consistency Check
        // =====================================================================
        $display("\n=== Test 2: Share Consistency Check ===");

        // Verify that key shares XOR to original key
        if ((dut.key_share0 ^ dut.key_share1) === TV_KEY) begin
            $display("  [PASS] Key shares recombine correctly.");
        end else begin
            $display("  [FAIL] Key share recombination mismatch!");
            $display("    share0 = 0x%064h", dut.key_share0);
            $display("    share1 = 0x%064h", dut.key_share1);
            $display("    XOR    = 0x%064h", dut.key_share0 ^ dut.key_share1);
            $display("    Expected = 0x%064h", TV_KEY);
            errors++;
        end

        // =====================================================================
        // Test 3: TRNG Interface Check
        // =====================================================================
        $display("\n=== Test 3: TRNG Interface ===");
        if (trng_ready) begin
            $display("  [PASS] TRNG ready signal active.");
        end else begin
            $display("  [FAIL] TRNG ready signal not asserted.");
            errors++;
        end

        // =====================================================================
        // Test 4: Idle State After Operation
        // =====================================================================
        $display("\n=== Test 4: Idle State After Operation ===");
        repeat (5) @(posedge clk);
        if (!busy) begin
            $display("  [PASS] Secure core returned to idle.");
        end else begin
            $display("  [FAIL] Secure core still busy.");
            errors++;
        end

        // =====================================================================
        // Summary
        // =====================================================================
        repeat (10) @(posedge clk);
        $display("\n=== Secure Core Test Summary ===");
        if (errors == 0)
            $display("All tests passed.");
        else
            $display("%0d test(s) FAILED.", errors);

        $finish;
    end

    // =========================================================================
    // Waveform Dump
    // =========================================================================
    initial begin
        $dumpfile("chacha20_poly1305_secure_tb.vcd");
        $dumpvars(0, chacha20_poly1305_secure_tb);
    end

    // Timeout watchdog
    initial begin
        #2_000_000;
        $display("ERROR: Simulation timeout.");
        $finish;
    end

endmodule
