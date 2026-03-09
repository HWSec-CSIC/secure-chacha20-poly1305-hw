// Top-level PRNG wrapper: TRNG seeding FSM + parallel Trivium instances.
module trivium_prng #(
                      parameter OUTPUT_LENGTH = 1024,               // Total random bits per cycle required
                      parameter TRIVIUM_BITS  = 256,                // Unrolling factor per Trivium
                      parameter TRNG_DBW      = 8                   // TRNG Data Bus Width
                      )
                      (
                       input  wire                     clk,
                       input  wire                     rst,          // Active High Reset
                       input  wire                     en,           // Enable (1 = Run, 0 = Pause)
                       input  wire                     reseed,       // Pulse to force a re-seed from TRNG
                       output wire [OUTPUT_LENGTH-1:0] random_data,  // The massive random bus
                       output wire                     valid         // High when data is cryptographically secure
                       );

    // =========================================================================
    // 1. Parameter Calculations & Constants
    // =========================================================================
    
    // Calculate how many Trivium cores we need (e.g., 1024 / 64 = 16 instances)
    localparam NUM_INSTANCES        = OUTPUT_LENGTH / TRIVIUM_BITS;
    
    // Total bits needed for Keys and IVs (80 Key + 80 IV = 160 bits per instance)
    localparam SEED_BITS_PER_INST   = 160; 
    localparam TOTAL_SEED_BITS      = NUM_INSTANCES * SEED_BITS_PER_INST;
    
    // Total Bytes needed from TRNG
    localparam TOTAL_BYTES          = TOTAL_SEED_BITS / TRNG_DBW;

    // FSM State Encodings
    localparam ST_RESET      = 3'd0;
    localparam ST_WAIT_TRNG  = 3'd1;
    localparam ST_READ_SEED  = 3'd2;
    localparam ST_LOAD_FARM  = 3'd3;
    localparam ST_WARMUP     = 3'd4;
    localparam ST_RUNNING    = 3'd5;

    // =========================================================================
    // 2. Internal Signals
    // =========================================================================

    // -- TRNG Signals --
    wire [TRNG_DBW-1:0] trng_data_out;
    wire                trng_valid_out;
    wire [15:0]         trng_occupation;
    reg                 trng_read_cmd;

    // -- FSM Signals --
    reg [2:0]                 state;            // Current State
    reg [TOTAL_SEED_BITS-1:0] seed_shift_reg;   // Massive register to hold all keys/IVs
    reg [15:0]                byte_counter;     // Track bytes read from TRNG
    
    // -- Trivium Control --
    reg  trivium_rst;                           // Controls the reset of all Trivium cores
    wire [NUM_INSTANCES-1:0] trivium_valid;     // Status of each core (1 bit per core)

    // =========================================================================
    // 3. The TRNG Instance
    // =========================================================================
    trng #(
            .TRNG_SIM(0),           //-- Simulation?
            .TRNG_UNITS(1),         //-- Number of TRNG Units
            .BANK_UNITS(1),         //-- Number of RO Banks per TRNG Unit
            .TRNG_SIZE(32768),      //-- TRNG memory size (bits)  
            .BLOCK_SIZE(TRNG_DBW),  //-- TRNG output size (bits)
            .Dbw(TRNG_DBW),         //-- Data Bus Width 
            .Bpc(2),                //-- Operation(2/4)/Characterization(32)
            .Nbc(8)                 //-- Number of bits of counters
            ) 
            u_trng_core 
            (
            .clock      (clk),
            .reset      (rst),
            .SD         (1'b0),
            .trng_ren   (trng_read_cmd), // Read Enable
            .trng_read  (trng_read_cmd), // Read Strobe
            .trng_valid (trng_valid_out),
            .trng_out   (trng_data_out),
            .trng_occp  (trng_occupation),
            .trng_full  (), // Unused
            .trng_wadd  (),
            .trng_radd  ()
            );

    // =========================================================================
    // 4. Single-Process FSM (Control & Datapath)
    // =========================================================================
    
    always @(posedge clk) begin
        if (rst) begin
            state           <= ST_RESET;
            byte_counter    <= 16'd0;
            seed_shift_reg  <= {TOTAL_SEED_BITS{1'b0}};
            trng_read_cmd   <= 1'b0;
            trivium_rst     <= 1'b1; // Hold Triviums in Reset
        end 
        else begin
            case (state)
                ST_RESET: begin
                    trivium_rst     <= 1'b1;
                    byte_counter    <= 16'd0;
                    state           <= ST_WAIT_TRNG;
                end

                ST_WAIT_TRNG: begin
                    trivium_rst     <= 1'b1;
                    trng_read_cmd   <= 1'b0;
                    
                    // Check if TRNG has enough bytes to fill our entire seed register
                    // We need 'TOTAL_BYTES'. trng_occupation tells us how many are ready.
                    if (trng_occupation >= TOTAL_BYTES) begin
                        state <= ST_READ_SEED;
                    end
                end

                ST_READ_SEED: begin
                    // 1. Request Data
                    // As long as we haven't finished, keep requesting
                    if (byte_counter < TOTAL_BYTES) begin
                        trng_read_cmd <= 1'b1;
                    end 
                    else begin
                        trng_read_cmd <= 1'b0;
                    end

                    // 2. Absorb Data (if valid)
                    if (trng_valid_out) begin
                        // Shift in the new byte from the LSB side
                        seed_shift_reg <= {seed_shift_reg[TOTAL_SEED_BITS-9:0], trng_data_out};
                        byte_counter   <= byte_counter + 1'b1;
                    end

                    // 3. Transition Condition
                    // If we have read all bytes and stored them
                    if (byte_counter >= TOTAL_BYTES) begin
                        trng_read_cmd <= 1'b0;
                        state         <= ST_LOAD_FARM;
                    end
                end

                ST_LOAD_FARM: begin
                    // We spend one cycle here with Trivium Reset still HIGH.
                    // This allows the 'seed_shift_reg' to stabilize on the
                    // Key/IV inputs of the Trivium instances before we release reset.
                    trivium_rst <= 1'b1;
                    state       <= ST_WARMUP;
                end

                ST_WARMUP: begin
                    // Release Reset.
                    // The Trivium modules will now load the Key/IV and start
                    // their internal 1152-cycle warm-up counter.
                    trivium_rst <= 1'b0;
                    
                    // Wait for all Trivium cores to signal they are ready.
                    // The '&' operator checks if ALL bits in trivium_valid are 1.
                    if (&trivium_valid) begin
                        state <= ST_RUNNING;
                    end
                end

                ST_RUNNING: begin
                    // Normal Operation.
                    trivium_rst <= 1'b0;
                    
                    // If the user requests a reseed, we reset the process.
                    if (reseed) begin
                        trivium_rst     <= 1'b1; // Reset them immediately
                        byte_counter    <= 16'd0;
                        state           <= ST_WAIT_TRNG;
                    end
                end
                
                default: state <= ST_RESET;
            endcase
        end
    end

    // =========================================================================
    // 5. The Trivium Farm Generation
    // =========================================================================
    genvar k;
    generate
        for (k = 0; k < NUM_INSTANCES; k = k + 1) begin : farm
            
            // Slice the massive seed register for this specific instance.
            // Each instance needs 160 bits: [80 bits Key | 80 bits IV]
            // We grab a 160-bit chunk from the big register.
            
            wire [79:0] key_slice;
            wire [79:0] iv_slice;
            
            // Assign slices
            // k*160 is the base index.
            assign key_slice = seed_shift_reg[(k*160) +: 80];      // Lower 80 bits of slice
            assign iv_slice  = seed_shift_reg[(k*160 + 80) +: 80]; // Upper 80 bits of slice

            trivium #(
                      .OUTPUT_BITS(TRIVIUM_BITS)
                      )
                      u_trivium_core 
                      (
                      .clk       (clk),
                      .rst       (trivium_rst),         // Controlled by FSM
                      .en        (en),                  // User flow control (Pause)
                      .key       (key_slice),
                      .iv        (iv_slice),
                      .stream_out(random_data[(k*TRIVIUM_BITS) +: TRIVIUM_BITS]),
                      .valid     (trivium_valid[k])     // Individual core status
                      );
        end
    endgenerate

    // =========================================================================
    // 6. System Output Logic
    // =========================================================================
    
    // The global 'valid' signal is high ONLY when:
    // 1. The FSM has reached the RUNNING state.
    // 2. All Trivium cores confirm they are valid (warm-up complete).
    assign valid = (state == ST_RUNNING) && (&trivium_valid);

endmodule
