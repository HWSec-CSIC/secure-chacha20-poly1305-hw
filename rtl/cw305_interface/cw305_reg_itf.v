/*

File derived from "ChipWhisperer Artix Target - Example of connections between example registers
and rest of system. -> 2020, NewAE Technology Inc"

Expanded ITF Register File for CW305 integration.
Provides:
   - i_control (8b), i_add (64b), i_data_in (64b)
   - o_data_out (64b), o_end_op (64b) latched on done
   - GO register (start pulse & busy readback)
   - Clock settings, user LED, identification, build timestamp

Address map (see cw305_defines_itf.v):
   0x20 I_CONTROL      (R/W)
   0x21 I_ADD          (R/W 64b)
   0x22 I_DATA_IN      (R/W 64b)
   0x23 O_DATA_OUT     (R   64b)
   0x24 O_END_OP       (R   64b)
   0x25 GO             (W: start pulse; R: busy bit0)
   0x26 CLKSETTINGS    (R/W)
   0x27 USER_LED       (R/W)
   0x28 TYPE           (R const)
   0x29 REV            (R const)
   0x2A IDENTIFY       (R const)
   0x2B BUILDTIME      (R multi-byte)

Done detection:
   - Uses bit0 transition of core_end_op_crypt[0]; latches outputs when it rises 0->1.
Busy behavior:
   - busy = asserted from start pulse until done edge.

*/

`default_nettype none
`timescale 1ns / 1ps
`include "cw305_defines_itf.v"

module cw305_reg_itf #(
   parameter pADDR_WIDTH = 21,
   parameter pBYTECNT_SIZE = 7
)(
   input  wire                                  usb_clk,
   input  wire                                  crypto_clk,
   input  wire                                  reset_i,
   input  wire [pADDR_WIDTH-pBYTECNT_SIZE-1:0]  reg_address,
   input  wire [pBYTECNT_SIZE-1:0]              reg_bytecnt,
   output reg  [7:0]                            read_data,
   input  wire [7:0]                            write_data,
   input  wire                                  reg_read,
   input  wire                                  reg_write,
   input  wire                                  reg_addrvalid,

   // Outputs to core
   output wire [63:0]                           O_i_control,
   output wire [63:0]                           O_i_add,
   output wire [63:0]                           O_i_data_in,
   output wire                                  O_start_pulse,
   output wire [4:0]                            O_clksettings,
   output wire [31:0]                           O_clkdiv_value,
   output wire                                  O_user_led,
   output wire                                  O_i_start_test,

   // Inputs from core
   input  wire [63:0]                           I_o_data_out,
   input  wire [63:0]                           I_o_end_op
);

   // ----------------------
   // USB domain registers
   // ----------------------
   reg [63:0]  reg_i_control;
   reg [63:0]  reg_i_add;
   reg [63:0]  reg_i_data_in;
   reg [4:0]   reg_clksettings;
   reg [31:0]  reg_i_clkdiv_value;
   reg         reg_user_led;
   reg         reg_i_start;

   // Start pulse generation (USB domain pulse -> crypto domain pulse)
   reg         reg_go_pulse_usb;
   wire        go_pulse_crypto;

   // Busy tracking (crypto domain)
   reg         busy_crypto;
   reg         busy_usb_sync1, busy_usb_sync2;

   // Latch outputs in crypto domain on done edge
   reg [63:0]  core_data_out_latched;
   reg [63:0]  core_end_op_latched;
   reg         end_bit_prev;
   // Detect rising edge of READ control (bit3) in crypto domain
   reg         read_bit_prev;
   reg         read_edge;       // 0->1 edge detector result (same cycle)
   reg         read_edge_dly;   // one-cycle delay to latch after PISO updates

   // CDC output to USB domain
   reg [63:0]  core_data_out_usb;
   reg [63:0]  core_end_op_usb;

   // CDC inputs to crypto domain
   (* ASYNC_REG = "TRUE" *) reg [7:0]   reg_i_control_crypt;
   (* ASYNC_REG = "TRUE" *) reg [63:0]  reg_i_add_crypt;
   (* ASYNC_REG = "TRUE" *) reg [63:0]  reg_i_data_in_crypt;

   // Assign outputs to core
   assign O_i_control   = reg_i_control_crypt;
   assign O_i_add       = reg_i_add_crypt;
   assign O_i_data_in   = reg_i_data_in_crypt;
   assign O_i_start_test= reg_i_start;
   assign O_clksettings = reg_clksettings;
   assign O_clkdiv_value = reg_i_clkdiv_value;
   assign O_user_led    = reg_user_led;
   assign O_start_pulse = go_pulse_crypto;

   // ----------------------
   // Write logic (USB clk)
   // ----------------------
   always @(posedge usb_clk) begin
      if (reset_i) begin
         reg_i_control   <= 8'h00;
         reg_i_add       <= 64'h0;
         reg_i_data_in   <= 64'h0;
         reg_clksettings <= 5'h0;
         reg_i_clkdiv_value <= 32'h0;
         reg_user_led    <= 1'b0;
         reg_go_pulse_usb<= 1'b0;
      end else begin
         reg_go_pulse_usb <= 1'b0; // default
         if (reg_addrvalid && reg_write) begin
            case (reg_address)
               `REG_ITF_I_CONTROL:     reg_i_control <= write_data;
               `REG_ITF_I_ADD:         reg_i_add[reg_bytecnt*8 +: 8] <= write_data;
               `REG_ITF_I_DATA_IN:     reg_i_data_in[reg_bytecnt*8 +: 8] <= write_data;
               `REG_ITF_CLKSETTINGS:   reg_clksettings <= write_data[4:0];
               `REG_ITF_CLKDIV_VALUE:  reg_i_clkdiv_value = write_data;
               `REG_ITF_USER_LED:      reg_user_led <= write_data[0];
               `REG_ITF_START_TEST:    reg_i_start <= write_data[0];
               `REG_ITF_GO:            reg_go_pulse_usb <= 1'b1; // writing any byte triggers start pulse
            endcase
         end
      end
   end

   // ----------------------
   // CDC inputs -> crypto
   // ----------------------
   always @(posedge crypto_clk) begin
      reg_i_control_crypt <= reg_i_control;
      reg_i_add_crypt     <= reg_i_add;
      reg_i_data_in_crypt <= reg_i_data_in;
   end

   // ----------------------
   // Start pulse CDC
   // ----------------------
   cdc_pulse U_itf_go_pulse (
      .reset_i    (reset_i),
      .src_clk    (usb_clk),
      .src_pulse  (reg_go_pulse_usb),
      .dst_clk    (crypto_clk),
      .dst_pulse  (go_pulse_crypto)
   );

   // ----------------------
   // Busy & Done tracking (crypto)
   // ----------------------
   always @(posedge crypto_clk) begin
      if (reset_i) begin
         busy_crypto    <= 1'b0;
         end_bit_prev   <= 1'b0;
         read_bit_prev  <= 1'b0;
         read_edge      <= 1'b0;
         read_edge_dly  <= 1'b0;
      end else begin
         // Start sets busy
         if (go_pulse_crypto)
            busy_crypto <= 1'b1;

         // Detect rising edge on bit0 of I_o_end_op
         end_bit_prev <= I_o_end_op[0];
         if (~end_bit_prev & I_o_end_op[0]) begin
            busy_crypto <= 1'b0; // operation complete
            core_data_out_latched <= I_o_data_out;
            core_end_op_latched   <= I_o_end_op;
         end

         // READ edge detect and delayed latch: many cores present data
         // one cycle after READ goes high. Detect edge now, latch next cycle.
         read_edge     <= (~read_bit_prev) & reg_i_control_crypt[3];
         read_edge_dly <= read_edge;
         read_bit_prev <= reg_i_control_crypt[3];
         if (read_edge_dly) begin
            core_data_out_latched <= I_o_data_out;
            core_end_op_latched   <= I_o_end_op;
         end
      end
   end

   // Output CDC back to USB
   always @(posedge usb_clk) begin
      core_data_out_usb <= core_data_out_latched;
      core_end_op_usb   <= core_end_op_latched;
      // busy flag sync (2FF)
      busy_usb_sync1 <= busy_crypto;
      busy_usb_sync2 <= busy_usb_sync1;
   end

   // ----------------------
   // Read mux (USB domain)
   // ----------------------
   reg [7:0] rd_mux;
   always @(*) begin
      if (reg_addrvalid && reg_read) begin
         case (reg_address)
            `REG_ITF_I_CONTROL:    rd_mux = reg_i_control;
            `REG_ITF_I_ADD:        rd_mux = reg_i_add[reg_bytecnt*8 +: 8];
            `REG_ITF_I_DATA_IN:    rd_mux = reg_i_data_in[reg_bytecnt*8 +: 8];
            `REG_ITF_O_DATA_OUT:   rd_mux = core_data_out_usb[reg_bytecnt*8 +: 8];
            `REG_ITF_O_END_OP:     rd_mux = core_end_op_usb[reg_bytecnt*8 +: 8];
            `REG_ITF_START_TEST:   rd_mux = {7'b0, reg_i_start};
            `REG_ITF_GO:           rd_mux = {7'b0, busy_usb_sync2};
            `REG_ITF_CLKSETTINGS:  rd_mux = {3'b0, reg_clksettings};
            `REG_ITF_CLKDIV_VALUE: rd_mux = {32'b0, reg_i_clkdiv_value};
            `REG_ITF_USER_LED:     rd_mux = {7'b0, reg_user_led};
            default:               rd_mux = 8'h00;
         endcase
      end else begin
         rd_mux = 8'h00;
      end
   end

   always @(posedge usb_clk)
      read_data <= rd_mux;

endmodule

`default_nettype wire
