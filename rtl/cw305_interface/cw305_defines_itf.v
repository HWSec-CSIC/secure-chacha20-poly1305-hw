/* 
Modified ITF Interface Register address definitions for custom ITF module integration.
Extended version with control, status, identification and build timestamp.
*/
`ifndef __CW305_DEFINES_ITF_V__
`define __CW305_DEFINES_ITF_V__

// Base block now starts at 0x00
`define REG_ITF_I_CONTROL      'h00   // [7:0]  i_control
`define REG_ITF_I_ADD          'h01   // [63:0] i_add
`define REG_ITF_I_DATA_IN      'h02   // [63:0] i_data_in
`define REG_ITF_O_DATA_OUT     'h03   // [63:0] o_data_out (latched copy)
`define REG_ITF_O_END_OP       'h04   // [63:0] o_end_op (latched copy)
`define REG_ITF_START_TEST     'h05   // [63:0] i_start

// Extended control/status & identification
`define REG_ITF_GO             'h06   // W: start pulse, R: busy flag (bit0) / reserved
`define REG_ITF_CLKSETTINGS    'h07   // Clock selection
`define REG_ITF_USER_LED       'h08   // User LED control
`define REG_ITF_CLKDIV_VALUE   'h09   // Clock divisior value 

`endif // __CW305_DEFINES_ITF_V__
