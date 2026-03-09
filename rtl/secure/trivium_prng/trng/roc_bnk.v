`default_nettype none
`timescale 1 ns / 10 ps

// Ring-oscillator bank (physically constrained).
module roc_bnk (
                input  wire       enx,      //-- Enable X
                input  wire       eny,      //-- Enable Y
                input  wire [7:0] cnf1,     //-- Configuration Selection #1
                input  wire [7:0] cnf2,     //-- Configuration Selection #2
                output wire [3:0] ro        //-- Pairs of RO Output
                );

    //-- This instance will be placed at the origin of wherever the placer decides to put this roc_bnk module.
    (* KEEP_HIERARCHY = "TRUE", RLOC = "X0Y0" *)
    roc CHALLENGE_0 (
                     .enx(enx),
                     .eny(eny),
                     .cnf(cnf2), // Even rows use cnf2
                     .ro(ro[1:0])
                     );

    //-- This instance will be placed one unit up in the Y direction, relative to the roc_bnk's origin.
    (* KEEP_HIERARCHY = "TRUE", RLOC = "X0Y1" *)
    roc CHALLENGE_1 (
                     .enx(enx),
                     .eny(eny),
                     .cnf(cnf1), // Odd rows use cnf1
                     .ro(ro[3:2])
                     );

endmodule
