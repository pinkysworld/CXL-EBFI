`timescale 1ns/1ps

module ebfi_metadata_ctrl #(
    parameter integer NUM_LINES = 16,
    parameter integer NUM_SLOTS = 4,
    parameter integer NUM_EPOCHS = 8,
    parameter integer CTR_BITS = 32,
    parameter integer WRITER_BITS = 8,
    parameter integer GEN_BITS = 8,
    parameter integer RETENTION_W = 2,
    parameter integer LINE_BITS = $clog2(NUM_LINES),
    parameter integer SLOT_BITS = $clog2(NUM_SLOTS),
    parameter integer EPOCH_BITS = $clog2(NUM_EPOCHS)
) (
    input  wire                    clk,
    input  wire                    rst_n,
    input  wire                    req_valid,
    output wire                    req_ready,
    input  wire [2:0]              req_op,
    input  wire [LINE_BITS-1:0]    req_line,
    input  wire [WRITER_BITS-1:0]  req_writer,
    input  wire [SLOT_BITS-1:0]    req_slot,
    input  wire [GEN_BITS-1:0]     req_generation,
    input  wire [EPOCH_BITS-1:0]   req_epoch,
    input  wire [CTR_BITS-1:0]     req_ctr,

    output reg                     rsp_valid,
    output reg  [2:0]              rsp_status,
    output reg  [SLOT_BITS-1:0]    rsp_slot,
    output reg  [GEN_BITS-1:0]     rsp_generation,
    output reg  [EPOCH_BITS-1:0]   rsp_epoch,
    output reg  [CTR_BITS-1:0]     rsp_ctr,
    output reg  [WRITER_BITS-1:0]  rsp_writer,

    output wire [EPOCH_BITS-1:0]   dbg_current_epoch,
    output wire [CTR_BITS-1:0]     dbg_auth_ctr,
    output wire [15:0]             dbg_live_refcount,
    output wire [15:0]             dbg_pending_refcount,
    output wire                    dbg_epoch_erased
);

    localparam [2:0] OP_RESERVE = 3'd0;
    localparam [2:0] OP_ENCRYPT = 3'd1;
    localparam [2:0] OP_COMMIT  = 3'd2;
    localparam [2:0] OP_CANCEL  = 3'd3;
    localparam [2:0] OP_TICKET  = 3'd4;
    localparam [2:0] OP_ADVANCE = 3'd5;
    localparam [2:0] OP_REVOKE  = 3'd6;

    localparam [2:0] ST_OK        = 3'd0;
    localparam [2:0] ST_BAD_TOKEN = 3'd1;
    localparam [2:0] ST_STALE     = 3'd2;
    localparam [2:0] ST_BLOCKED   = 3'd3;
    localparam [2:0] ST_UNINIT    = 3'd4;
    localparam [2:0] ST_FULL      = 3'd5;
    localparam [2:0] ST_OVERFLOW  = 3'd6;

    localparam [1:0] SLOT_FREE      = 2'd0;
    localparam [1:0] SLOT_RESERVED  = 2'd1;
    localparam [1:0] SLOT_ENCRYPTED = 2'd2;

    reg [EPOCH_BITS-1:0] current_epoch;
    reg [CTR_BITS-1:0] alloc_ctr [0:NUM_LINES-1];
    reg [CTR_BITS-1:0] auth_ctr [0:NUM_LINES-1];
    reg [EPOCH_BITS-1:0] auth_epoch [0:NUM_LINES-1];
    reg [WRITER_BITS-1:0] auth_writer [0:NUM_LINES-1];
    reg auth_valid [0:NUM_LINES-1];

    reg [15:0] live_refcount [0:NUM_EPOCHS-1];
    reg [15:0] pending_refcount [0:NUM_EPOCHS-1];
    reg epoch_valid [0:NUM_EPOCHS-1];
    reg epoch_erased [0:NUM_EPOCHS-1];

    reg [1:0] slot_state [0:NUM_SLOTS-1];
    reg [LINE_BITS-1:0] slot_line [0:NUM_SLOTS-1];
    reg [EPOCH_BITS-1:0] slot_epoch [0:NUM_SLOTS-1];
    reg [CTR_BITS-1:0] slot_ctr [0:NUM_SLOTS-1];
    reg [WRITER_BITS-1:0] slot_writer [0:NUM_SLOTS-1];
    reg [GEN_BITS-1:0] slot_generation [0:NUM_SLOTS-1];

    reg free_found;
    reg [SLOT_BITS-1:0] free_slot;
    integer i;

    assign req_ready = 1'b1;
    assign dbg_current_epoch = current_epoch;
    assign dbg_auth_ctr = auth_ctr[req_line];
    assign dbg_live_refcount = live_refcount[req_epoch];
    assign dbg_pending_refcount = pending_refcount[req_epoch];
    assign dbg_epoch_erased = epoch_erased[req_epoch];

    always @* begin
        free_found = 1'b0;
        free_slot = {SLOT_BITS{1'b0}};
        for (i = 0; i < NUM_SLOTS; i = i + 1) begin
            if (!free_found && slot_state[i] == SLOT_FREE) begin
                free_found = 1'b1;
                free_slot = i[SLOT_BITS-1:0];
            end
        end
    end

    wire token_matches =
        req_slot < NUM_SLOTS &&
        slot_generation[req_slot] == req_generation &&
        slot_line[req_slot] == req_line &&
        slot_epoch[req_slot] == req_epoch &&
        slot_ctr[req_slot] == req_ctr &&
        slot_writer[req_slot] == req_writer;

    always @(posedge clk) begin
        if (!rst_n) begin
            current_epoch <= {{(EPOCH_BITS-1){1'b0}}, 1'b1};
            rsp_valid <= 1'b0;
            rsp_status <= ST_OK;
            rsp_slot <= {SLOT_BITS{1'b0}};
            rsp_generation <= {GEN_BITS{1'b0}};
            rsp_epoch <= {EPOCH_BITS{1'b0}};
            rsp_ctr <= {CTR_BITS{1'b0}};
            rsp_writer <= {WRITER_BITS{1'b0}};
            for (i = 0; i < NUM_LINES; i = i + 1) begin
                alloc_ctr[i] <= {CTR_BITS{1'b0}};
                auth_ctr[i] <= {CTR_BITS{1'b0}};
                auth_epoch[i] <= {EPOCH_BITS{1'b0}};
                auth_writer[i] <= {WRITER_BITS{1'b0}};
                auth_valid[i] <= 1'b0;
            end
            for (i = 0; i < NUM_EPOCHS; i = i + 1) begin
                live_refcount[i] <= 16'd0;
                pending_refcount[i] <= 16'd0;
                epoch_valid[i] <= (i == 1);
                epoch_erased[i] <= 1'b0;
            end
            for (i = 0; i < NUM_SLOTS; i = i + 1) begin
                slot_state[i] <= SLOT_FREE;
                slot_line[i] <= {LINE_BITS{1'b0}};
                slot_epoch[i] <= {EPOCH_BITS{1'b0}};
                slot_ctr[i] <= {CTR_BITS{1'b0}};
                slot_writer[i] <= {WRITER_BITS{1'b0}};
                slot_generation[i] <= {GEN_BITS{1'b0}};
            end
        end else begin
            rsp_valid <= 1'b0;
            if (req_valid) begin
                rsp_valid <= 1'b1;
                rsp_status <= ST_OK;
                rsp_slot <= req_slot;
                rsp_generation <= req_generation;
                rsp_epoch <= req_epoch;
                rsp_ctr <= req_ctr;
                rsp_writer <= req_writer;

                case (req_op)
                    OP_RESERVE: begin
                        if (!free_found) begin
                            rsp_status <= ST_FULL;
                        end else if (&alloc_ctr[req_line]) begin
                            rsp_status <= ST_OVERFLOW;
                        end else begin
                            alloc_ctr[req_line] <= alloc_ctr[req_line] + 1'b1;
                            slot_state[free_slot] <= SLOT_RESERVED;
                            slot_line[free_slot] <= req_line;
                            slot_epoch[free_slot] <= current_epoch;
                            slot_ctr[free_slot] <= alloc_ctr[req_line] + 1'b1;
                            slot_writer[free_slot] <= req_writer;
                            slot_generation[free_slot] <=
                                slot_generation[free_slot] + 1'b1;
                            pending_refcount[current_epoch] <=
                                pending_refcount[current_epoch] + 1'b1;
                            rsp_slot <= free_slot;
                            rsp_generation <=
                                slot_generation[free_slot] + 1'b1;
                            rsp_epoch <= current_epoch;
                            rsp_ctr <= alloc_ctr[req_line] + 1'b1;
                            rsp_writer <= req_writer;
                        end
                    end

                    OP_ENCRYPT: begin
                        if (!token_matches ||
                            slot_state[req_slot] != SLOT_RESERVED ||
                            !epoch_valid[req_epoch] ||
                            epoch_erased[req_epoch]) begin
                            rsp_status <= ST_BAD_TOKEN;
                        end else begin
                            slot_state[req_slot] <= SLOT_ENCRYPTED;
                        end
                    end

                    OP_COMMIT: begin
                        if (!token_matches ||
                            slot_state[req_slot] != SLOT_ENCRYPTED) begin
                            rsp_status <= ST_BAD_TOKEN;
                        end else begin
                            slot_state[req_slot] <= SLOT_FREE;
                            pending_refcount[req_epoch] <=
                                pending_refcount[req_epoch] - 1'b1;
                            if (auth_valid[req_line] &&
                                req_ctr <= auth_ctr[req_line]) begin
                                rsp_status <= ST_STALE;
                            end else begin
                                if (auth_valid[req_line] &&
                                    auth_epoch[req_line] != req_epoch) begin
                                    live_refcount[auth_epoch[req_line]] <=
                                        live_refcount[auth_epoch[req_line]] - 1'b1;
                                    live_refcount[req_epoch] <=
                                        live_refcount[req_epoch] + 1'b1;
                                end else if (!auth_valid[req_line]) begin
                                    live_refcount[req_epoch] <=
                                        live_refcount[req_epoch] + 1'b1;
                                end
                                auth_valid[req_line] <= 1'b1;
                                auth_epoch[req_line] <= req_epoch;
                                auth_ctr[req_line] <= req_ctr;
                                auth_writer[req_line] <= req_writer;
                            end
                        end
                    end

                    OP_CANCEL: begin
                        if (!token_matches ||
                            slot_state[req_slot] == SLOT_FREE) begin
                            rsp_status <= ST_BAD_TOKEN;
                        end else begin
                            slot_state[req_slot] <= SLOT_FREE;
                            pending_refcount[req_epoch] <=
                                pending_refcount[req_epoch] - 1'b1;
                        end
                    end

                    OP_TICKET: begin
                        if (!auth_valid[req_line]) begin
                            rsp_status <= ST_UNINIT;
                        end else begin
                            rsp_epoch <= auth_epoch[req_line];
                            rsp_ctr <= auth_ctr[req_line];
                            rsp_writer <= auth_writer[req_line];
                        end
                    end

                    OP_ADVANCE: begin
                        if (current_epoch == NUM_EPOCHS-1) begin
                            rsp_status <= ST_OVERFLOW;
                        end else begin
                            current_epoch <= current_epoch + 1'b1;
                            epoch_valid[current_epoch + 1'b1] <= 1'b1;
                            epoch_erased[current_epoch + 1'b1] <= 1'b0;
                            rsp_epoch <= current_epoch + 1'b1;
                        end
                    end

                    OP_REVOKE: begin
                        if (!epoch_valid[req_epoch] ||
                            epoch_erased[req_epoch]) begin
                            rsp_status <= ST_UNINIT;
                        end else if ((req_epoch + RETENTION_W > current_epoch) ||
                                     live_refcount[req_epoch] != 0 ||
                                     pending_refcount[req_epoch] != 0) begin
                            rsp_status <= ST_BLOCKED;
                        end else begin
                            epoch_valid[req_epoch] <= 1'b0;
                            epoch_erased[req_epoch] <= 1'b1;
                        end
                    end

                    default: rsp_status <= ST_BAD_TOKEN;
                endcase
            end
        end
    end

endmodule
