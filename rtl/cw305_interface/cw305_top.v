/* 

File derived from "ChipWhisperer Artix Target - Example of connections between top modules of the interface. -> 2020, NewAE Technology Inc"

*/

`timescale 1ns / 1ps
`default_nettype none 

module cw305_top #(
    parameter pBYTECNT_SIZE = 7,
    parameter pADDR_WIDTH = 21,
    parameter pPT_WIDTH = 128,
    parameter pCT_WIDTH = 128,
    parameter pKEY_WIDTH = 128    
)(
    // USB Interface
    input wire                          usb_clk,        // Clock
`ifdef SS2_WRAPPER
    output wire                         usb_clk_buf,    // if needed by parent module
    input  wire [7:0]                   usb_data,
    output wire [7:0]                   usb_dout,
`else
    inout wire [7:0]                    usb_data,       // Data for write/read
`endif
    input wire [pADDR_WIDTH-1:0]        usb_addr,       // Address
    input wire                          usb_rdn,        // !RD, low when addr valid for read
    input wire                          usb_wrn,        // !WR, low when data+addr valid for write
    input wire                          usb_cen,        // !CE, active low chip enable
    input wire                          usb_trigger,    // High when trigger requested

    // Buttons/LEDs on Board
    input wire                          j16_sel,        // DIP switch J16
    input wire                          k16_sel,        // DIP switch K16
    input wire                          k15_sel,        // DIP switch K15
    input wire                          l14_sel,        // DIP Switch L14
    input wire                          pushbutton,     // Pushbutton SW4, connected to R1, used here as reset
    output wire                         led1,           // red LED
    output wire                         led2,           // green LED
    output wire                         led3,           // blue LED

    // PLL
    input wire                          pll_clk1,       //PLL Clock Channel #1
    //input wire                        pll_clk2,       //PLL Clock Channel #2 (unused in this example)

    // 20-Pin Connector Stuff
    output wire                         tio_trigger,
    output wire                         tio_clkout,
    input  wire                         tio_clkin
    );
    
    wire isout;
    wire [pADDR_WIDTH-pBYTECNT_SIZE-1:0] reg_address;
    wire [pBYTECNT_SIZE-1:0] reg_bytecnt;
    wire reg_addrvalid;
    wire [7:0] write_data;
    wire [7:0] read_data;
    wire reg_read;
    wire reg_write;
    wire [4:0] clk_settings;
    wire user_led;
    wire itf_start_pulse;
    wire itf_start_test;
    wire [31:0] itf_clk_div_value;
    wire crypt_clk, crypt_clk_div;    

    wire resetn = pushbutton;
    wire reset = !resetn;
    
    `ifndef SS2_WRAPPER
        wire usb_clk_buf;
        wire [7:0] usb_dout;
        assign usb_data = isout? usb_dout : 8'bZ;
    `endif

    // USB CLK Heartbeat
    reg [24:0] usb_timer_heartbeat;
    always @(posedge usb_clk_buf) usb_timer_heartbeat <= usb_timer_heartbeat +  25'd1;
    assign led1 = usb_timer_heartbeat[24];

    // CRYPT CLK Heartbeat
    reg [22:0] crypt_clk_heartbeat;
    always @(posedge crypt_clk_div) crypt_clk_heartbeat <= crypt_clk_heartbeat +  23'd1;
    assign led2 = crypt_clk_heartbeat[22];


    cw305_usb_reg_fe #(
        .pBYTECNT_SIZE           (pBYTECNT_SIZE),
        .pADDR_WIDTH             (pADDR_WIDTH)
    ) U_usb_reg_fe (
        .rst                     (reset),
        .usb_clk                 (usb_clk_buf), 
        .usb_din                 (usb_data), 
        .usb_dout                (usb_dout), 
        .usb_rdn                 (usb_rdn), 
        .usb_wrn                 (usb_wrn),
        .usb_cen                 (usb_cen),
        .usb_alen                (1'b0),                
        .usb_addr                (usb_addr),
        .usb_isout               (isout), 
        .reg_address             (reg_address), 
        .reg_bytecnt             (reg_bytecnt), 
        .reg_datao               (write_data), 
        .reg_datai               (read_data),
        .reg_read                (reg_read), 
        .reg_write               (reg_write), 
        .reg_addrvalid           (reg_addrvalid)
    );

    // ITF custom interface registers
    wire [63:0] itf_i_control;
    wire [63:0] itf_i_add;
    wire [63:0] itf_i_data_in;
    wire [63:0] itf_o_data_out;
    wire [63:0] itf_o_end_op;
    wire        itf_o_cw_trigger;
    
    reg [63:0] o_end_op_sync_1, o_end_op_sync_2;
    reg [63:0] o_data_out_sync_1, o_data_out_sync_2;

    always @(posedge crypt_clk) begin
        o_end_op_sync_1 <= itf_o_end_op;
        o_end_op_sync_2 <= o_end_op_sync_1;
        o_data_out_sync_1 <= itf_o_data_out;
        o_data_out_sync_2 <= o_data_out_sync_1;
    end
    
    // Total output data width (10 x 64-bit registers = 640 bits)
    localparam TOTAL_WIDTH = 10 * 64; 
    wire done_fast_sync = o_end_op_sync_2[0];
    
    wire [TOTAL_WIDTH-1:0] aead_result_slow;   
    reg  [TOTAL_WIDTH-1:0] result_shadow;      
    reg  [63:0]            data_out_mux;       
    
    // Capture data when 'Done' is synchronized to the fast domain
    always @(posedge crypt_clk) begin
        if (done_fast_sync) begin
            result_shadow <= aead_result_slow;
        end
    end

    // Read multiplexer (combinational, fast clock domain)
    integer i;
    always @(*) begin
        data_out_mux = 64'd0;
        data_out_mux = result_shadow[itf_i_add[3:0] * 64 +: 64];
    end

    cw305_reg_itf #(
        .pBYTECNT_SIZE           (pBYTECNT_SIZE),
        .pADDR_WIDTH             (pADDR_WIDTH)
    ) U_reg_itf (
        .reset_i                 (reset),
        .crypto_clk              (crypt_clk), 
        .usb_clk                 (usb_clk_buf),
        .reg_address             (reg_address[pADDR_WIDTH-pBYTECNT_SIZE-1:0]),
        .reg_bytecnt             (reg_bytecnt),
        .read_data               (read_data),
        .write_data              (write_data),
        .reg_read                (reg_read),
        .reg_write               (reg_write),
        .reg_addrvalid           (reg_addrvalid),
        .O_i_control             (itf_i_control),
        .O_i_add                 (itf_i_add),
        .O_i_data_in             (itf_i_data_in),
        .O_i_start_test          (itf_start_test),
        .O_start_pulse           (itf_start_pulse),
        .O_clksettings           (clk_settings),
        .O_clkdiv_value          (itf_clk_div_value),
        .O_user_led              (user_led),
        .I_o_data_out            (data_out_mux),
        .I_o_end_op              (o_end_op_sync_2)
    );

    clocks U_clocks (
        .usb_clk                 (usb_clk),
        .usb_clk_buf             (usb_clk_buf),
        .I_j16_sel               (j16_sel),
        .I_k16_sel               (k16_sel),
        .I_clock_reg             (clk_settings),
        .I_cw_clkin              (tio_clkin),
        .I_pll_clk1              (pll_clk1),
        .O_cw_clkout             (tio_clkout),
        .O_cryptoclk             (crypt_clk)
    );
    
    clock_divider U_clk_div (
        .clock_in(crypt_clk),
        .divisor_in(itf_clk_div_value),   
        .clock_out(crypt_clk_div)
    );
    
    reg i_start_sync_1, i_start_sync_2;
    
    always @(posedge crypt_clk_div) begin
        i_start_sync_1 <= itf_start_test; 
        i_start_sync_2 <= i_start_sync_1;
    end

  // BEGIN HERE YOUR CRYPTO MODULE CONNECTIONS
  // Instantiate your DUT interface module
  //**
  
  aead_itf #() U_aead_itf (
        .i_clk                   (crypt_clk_div),
        .i_rst                   (reset),
        .i_start                 (i_start_sync_2),
        .i_control               (itf_i_control),
        .i_add                   (itf_i_add),
        .i_data_in               (itf_i_data_in),
        .o_data_out              (),
        .o_end_op                (itf_o_end_op),
        .o_busy                  (tio_trigger),
        .o_result_digest         (aead_result_slow)
    );
    
    // **
    // END HERE YOUR CRYPTO MODULE CONNECTIONS

    // LED user-controlled 
    assign led3 = user_led;
    
endmodule