`default_nettype none
`timescale 1 ns / 10 ps

// Binary counter for RO-based TRNG.
module roc_cnt #(
                 parameter Nbc = 14                     //-- Maximum Number of Bits of Counter
                 ) 
                 (
                  input  wire           clk,            //-- Clock Signal (RO)
                  input  wire           rst,            //-- Reset Active High
                  // input  wire [Nbc-1:0] sel_nbc,        //-- Select Bits of the Counter
                  input  wire           count_en,       //-- Count Enable
                  output reg            full,           //-- Full Signal
                  output reg  [Nbc-1:0] counter         //-- Counter Output
                  );

    localparam [Nbc-1:0] MASK = { {(Nbc-3){1'b1}}, 3'b100 };

    // wire [Nbc-1:0] mask = MASK & sel_nbc;
    
    //-- Counter logic
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            counter <= 0;
            full    <= 1'b0;
        end 
        else if (count_en) begin
            counter <= counter + 1;
            
            // The 'full' signal becomes '1' when the counter reaches the MASK value.
            // It is "sticky" and will not go low again until a reset.
            // The check uses the value of counter from *before* the increment
            if (counter == /* mask */ MASK) begin
                full <= 1'b1;
            end
        end
    end

endmodule
