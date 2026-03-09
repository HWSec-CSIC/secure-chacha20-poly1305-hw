`default_nettype none
// PISO and SIPO memory interfaces for the AEAD data path.

module piso #(
              parameter R_DATA_WIDTH = 32,
              parameter N_REG = 8,
              parameter N_REG_BITS = (N_REG == 1) ? 1 : $clog2(N_REG)
              )
             (
              input  wire clk,                                          //-- Clock Signal
              input  wire read,                                         //-- Read Signal
              input  wire [N_REG_BITS-1:0] addr,                        //-- Address
              input  wire [R_DATA_WIDTH*N_REG-1:0] din,                 //-- Parallel Input 
              output reg  [R_DATA_WIDTH-1:0] dout                       //-- Serial Output
              );
    

    always @(posedge clk) begin
        if (read == 0)
            dout <= 0;
        else
            dout <= din[R_DATA_WIDTH*addr+:R_DATA_WIDTH]; 
    end

endmodule

module sipo #(
              parameter R_DATA_WIDTH = 32,
              parameter N_REG = 8,
              parameter N_REG_BITS = (N_REG == 1) ? 1 : $clog2(N_REG)
              )
             (
              input  wire clk,                                          //-- Clock Signal 
              input  wire rst,                                          //-- Reset Signal 
              input  wire load,                                         //-- Load Signal
              input  wire [N_REG_BITS-1:0] addr,                        //-- Address
              input  wire [R_DATA_WIDTH-1:0] din,                       //-- Serial Input 
              output reg  [R_DATA_WIDTH*N_REG-1:0] dout                 //-- Parallel Output
              );
    
    
    always @(posedge clk) begin
        if (rst)
            dout <= 0;
        else if (load)
            dout[R_DATA_WIDTH*addr+:R_DATA_WIDTH] <= din;
    end
    
endmodule