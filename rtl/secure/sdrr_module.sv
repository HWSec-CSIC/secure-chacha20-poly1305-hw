// =============================================================================
// sdrr_module.sv
// Shared Domain Re-Randomization (SDRR) Module
// Injects fresh randomness at critical pipeline stages to maintain
// security margins against higher-order leakage.
// =============================================================================

`timescale 1ns / 1ps

module sdrr_module #(
    parameter WIDTH     = 32,
    parameter NUM_SHARES = 2
)(
    input  logic                          clk,
    input  logic                          rst_n,
    input  logic                          en,

    // Fresh randomness input
    input  logic [WIDTH-1:0]              fresh_rand,

    // Input shares
    input  logic [WIDTH-1:0]              share_in [0:NUM_SHARES-1],

    // Re-randomized output shares
    output logic [WIDTH-1:0]              share_out [0:NUM_SHARES-1]
);

    // =========================================================================
    // SDRR Logic
    // Re-randomization preserves the shared secret:
    //   share_out[0] = share_in[0] ^ fresh_rand
    //   share_out[1] = share_in[1] ^ fresh_rand
    // Since: share_out[0] ^ share_out[1]
    //      = (share_in[0] ^ r) ^ (share_in[1] ^ r)
    //      = share_in[0] ^ share_in[1]           (r cancels)
    //
    // This refreshes the statistical distribution of each share
    // while preserving the unmasked value.
    // =========================================================================

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < NUM_SHARES; i++) begin
                share_out[i] <= {WIDTH{1'b0}};
            end
        end else if (en) begin
            share_out[0] <= share_in[0] ^ fresh_rand;
            share_out[1] <= share_in[1] ^ fresh_rand;
        end
    end

endmodule
