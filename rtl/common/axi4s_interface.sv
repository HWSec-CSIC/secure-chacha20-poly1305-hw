// =============================================================================
// axi4s_interface.sv
// AXI4-Stream Slave/Master Interface Wrapper
// Shared module used by both the standard and secure architectures.
// =============================================================================

`timescale 1ns / 1ps

module axi4s_interface #(
    parameter DATA_WIDTH = 128,
    parameter USER_WIDTH = 1
)(
    input  logic                    clk,
    input  logic                    rst_n,

    // AXI4-Stream Slave (input)
    input  logic [DATA_WIDTH-1:0]   s_axis_tdata,
    input  logic                    s_axis_tvalid,
    output logic                    s_axis_tready,
    input  logic                    s_axis_tlast,
    input  logic [USER_WIDTH-1:0]   s_axis_tuser,

    // AXI4-Stream Master (output)
    output logic [DATA_WIDTH-1:0]   m_axis_tdata,
    output logic                    m_axis_tvalid,
    input  logic                    m_axis_tready,
    output logic                    m_axis_tlast,
    output logic [USER_WIDTH-1:0]   m_axis_tuser,

    // Internal datapath interface
    output logic [DATA_WIDTH-1:0]   data_in,
    output logic                    data_in_valid,
    output logic                    data_in_last,
    input  logic                    data_in_ready,

    input  logic [DATA_WIDTH-1:0]   data_out,
    input  logic                    data_out_valid,
    input  logic                    data_out_last,
    output logic                    data_out_ready
);

    // Slave side: pass through with flow control
    assign data_in       = s_axis_tdata;
    assign data_in_valid = s_axis_tvalid;
    assign data_in_last  = s_axis_tlast;
    assign s_axis_tready = data_in_ready;

    // Master side: pass through with flow control
    assign m_axis_tdata  = data_out;
    assign m_axis_tvalid = data_out_valid;
    assign m_axis_tlast  = data_out_last;
    assign data_out_ready = m_axis_tready;

    // User signal passthrough (registered)
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            m_axis_tuser <= {USER_WIDTH{1'b0}};
        end else if (s_axis_tvalid && s_axis_tready) begin
            m_axis_tuser <= s_axis_tuser;
        end
    end

endmodule
