// Clock Divider Module
// Description:
// This module implements a simple clock divider that takes an input clock and divides it by a specified divisor to produce a slower output clock. 

module clock_divider (
    input  wire        clock_in,
    input  wire [31:0] divisor_in, 
    output reg         clock_out
);

    reg [31:0] counter = 32'd0;

    always @(posedge clock_in)
    begin
        if (counter >= (divisor_in - 1)) begin
            counter <= 32'd0;
        end else begin
            counter <= counter + 32'd1;
        end

        if (counter < (divisor_in >> 1)) begin
            clock_out <= 1'b1;
        end else begin
            clock_out <= 1'b0;
        end
    end
endmodule