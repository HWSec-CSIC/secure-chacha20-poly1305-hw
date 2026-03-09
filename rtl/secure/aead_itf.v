`default_nettype none
`include "cw305_defines_itf.v"
// AEAD interface (masked): manages 3 ciphertext shares, SIPO input, PISO output.

module aead_itf#(
                 parameter  PIPELINE_STAGES = 2,
                 parameter  CIPHER_ROUNDS = 20,
                 parameter  RECURSION_DEPTH = 0,
                 localparam WIDTH      = 64,
                 localparam IN_REG     = 17,
                 localparam OUT_REG    = 10
                )
                (
                  input  wire             i_clk,                    //-- Clock Signal
                  input  wire             i_rst,                    //-- Reset Signal - Active high                   
                  input  wire             i_start,                  //-- Start hardcoded test           
                  input  wire [WIDTH-1:0] i_control,                //-- Control Signal: {read, load, rst_itf, rst}  
                  input  wire [WIDTH-1:0] i_add,                    //-- Address
                  input  wire [WIDTH-1:0] i_data_in,                //-- Data Input
                  output wire [WIDTH-1:0] o_data_out,               //-- Data Output
                  output wire [WIDTH-1:0] o_end_op,                 //-- End Operation Signal 
                  output wire             o_busy,                    //-- Sets to 1 when AEAD operation begins (register output)
                  output wire [(OUT_REG*WIDTH)-1:0] o_result_digest
                 );
                  
    //--------------------------------------
	//-- Wires & Registers
	//--------------------------------------

    wire rst;
    wire rst_itf;
    wire load;
    wire read;
    wire enc;
	wire [1:0] next_blk;
    
    assign rst      = i_control[0] | i_rst;     
    assign rst_itf  = i_control[1] | i_rst;
    assign load     = i_control[2];
    assign read     = i_control[3];
    assign enc      = i_control[4];
    assign next_blk = i_control[6:5];
    
    //-- Sipo Input
    wire [IN_REG*WIDTH-1:0]  data_aead_in;
    //-- Piso input
    wire [OUT_REG*WIDTH-1:0] data_aead_out;
    
    //-- AEAD Inputs
	wire [4*WIDTH-1:0] key;
	wire [95:0] nonce;
	wire [2*WIDTH-1:0] aad;
	wire [31:0] aad_len;
	wire [8*WIDTH-1:0] plaintext;
	wire [31:0] pt_len;
	
	assign aad_len      = data_aead_in[31:0];
	assign pt_len       = data_aead_in[63:32];
	
	// splitted nonce (LSB)
	assign nonce[63:0]  = data_aead_in[2*WIDTH-1:WIDTH];
	// splitted nonce (MSB)
	assign nonce[95:64] = data_aead_in[2*WIDTH + 31:2*WIDTH];
	assign aad	  		= data_aead_in[5*WIDTH-1:3*WIDTH];	
    assign key	  		= data_aead_in[9*WIDTH-1:5*WIDTH];
    assign plaintext 	= data_aead_in[17*WIDTH-1:9*WIDTH];  
    
    //-- Intermediate signals
    wire [511:0] ct_shares [0:2];

    //-- AEAD Outputs
	wire [8*WIDTH-1:0] ciphertext;
	wire [2*WIDTH-1:0] tag;
	wire [1:0] valid;
	wire ready;
	wire [12:0] busy_cnt;
	
	assign ciphertext = (!o_busy) ? (ct_shares[2] ^ct_shares[1] ^ ct_shares[0]) : 0; // undo the shares when not operating
    assign data_aead_out[8*WIDTH-1:0] = ciphertext;
    assign data_aead_out[10*WIDTH-1:8*WIDTH] = tag;
    
    //--------------------------------------
	//-- SIPO          
	//--------------------------------------
    
    sipo #(.R_DATA_WIDTH(WIDTH), .N_REG(IN_REG)) SIPO (
	                                                   .clk(i_clk),
	                                                   .rst(rst_itf),
	                                                   .load(load),
						                               .addr(i_add[4:0]),
						                               .din(i_data_in),
						                               .dout(data_aead_in)
						                               ); 
                                                      

    //--------------------------------------
	//-- AEAD                        
	//--------------------------------------
        
	aead_core_top_msk #(.PIPELINE_STAGES(PIPELINE_STAGES), 
	                    .CIPHER_ROUNDS(CIPHER_ROUNDS), 
	                    .RECURSION_DEPTH(RECURSION_DEPTH)
	           )AEAD(
				 .clk(i_clk),
				 .rst(rst),
				 .enc(enc),
				 .start(i_start),
				 .next_blk(next_blk),
				 .key(key),
				 .nonce(nonce),
				 .aad(aad),
				 .aad_len(aad_len),
				 .plaintext(plaintext),
				 .pt_len(pt_len),
				 .ciphertext_sh1(ct_shares[0]),
				 .ciphertext_sh2(ct_shares[1]),
				 .ciphertext_sh3(ct_shares[2]),				 
				 .tag(tag),
				 .valid(valid),
				 .ready(ready),
				 .busy(o_busy),
				 .busy_cnt(busy_cnt)
				 );     
    
//    //--------------------------------------
//	//-- PISO              
//	//--------------------------------------
    
//    piso #(.R_DATA_WIDTH(WIDTH), .N_REG(OUT_REG)) PISO(
//						                               .clk(i_clk),
//						                               .read(read),
//						                               .addr(i_add[3:0]),
//						                               .din(data_aead_out),
//						                               .dout(o_data_out)
//						                               );
    

   assign o_end_op[0]           = ready;
   assign o_end_op[2:1]         = valid;
   assign o_end_op[15:3]        = busy_cnt;
   assign o_end_op[WIDTH-1:16]  = 0;
   
   assign o_result_digest = data_aead_out;
       
endmodule