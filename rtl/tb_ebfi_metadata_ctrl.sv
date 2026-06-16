`timescale 1ns/1ps

module tb_ebfi_metadata_ctrl;
    localparam OP_RESERVE = 3'd0;
    localparam OP_ENCRYPT = 3'd1;
    localparam OP_COMMIT  = 3'd2;
    localparam OP_CANCEL  = 3'd3;
    localparam OP_TICKET  = 3'd4;
    localparam OP_ADVANCE = 3'd5;
    localparam OP_REVOKE  = 3'd6;

    localparam ST_OK        = 3'd0;
    localparam ST_BAD_TOKEN = 3'd1;
    localparam ST_STALE     = 3'd2;
    localparam ST_BLOCKED   = 3'd3;

    reg clk = 0;
    reg rst_n = 0;
    reg req_valid = 0;
    reg [2:0] req_op = 0;
    reg [3:0] req_line = 0;
    reg [7:0] req_writer = 0;
    reg [1:0] req_slot = 0;
    reg [7:0] req_generation = 0;
    reg [2:0] req_epoch = 0;
    reg [31:0] req_ctr = 0;

    wire req_ready;
    wire rsp_valid;
    wire [2:0] rsp_status;
    wire [1:0] rsp_slot;
    wire [7:0] rsp_generation;
    wire [2:0] rsp_epoch;
    wire [31:0] rsp_ctr;
    wire [7:0] rsp_writer;
    wire [2:0] dbg_current_epoch;
    wire [31:0] dbg_auth_ctr;
    wire [15:0] dbg_live_refcount;
    wire [15:0] dbg_pending_refcount;
    wire dbg_epoch_erased;

    reg [1:0] slots [0:3];
    reg [7:0] generations [0:3];
    reg [2:0] epochs [0:3];
    reg [31:0] counters [0:3];

    ebfi_metadata_ctrl dut (
        .clk(clk),
        .rst_n(rst_n),
        .req_valid(req_valid),
        .req_ready(req_ready),
        .req_op(req_op),
        .req_line(req_line),
        .req_writer(req_writer),
        .req_slot(req_slot),
        .req_generation(req_generation),
        .req_epoch(req_epoch),
        .req_ctr(req_ctr),
        .rsp_valid(rsp_valid),
        .rsp_status(rsp_status),
        .rsp_slot(rsp_slot),
        .rsp_generation(rsp_generation),
        .rsp_epoch(rsp_epoch),
        .rsp_ctr(rsp_ctr),
        .rsp_writer(rsp_writer),
        .dbg_current_epoch(dbg_current_epoch),
        .dbg_auth_ctr(dbg_auth_ctr),
        .dbg_live_refcount(dbg_live_refcount),
        .dbg_pending_refcount(dbg_pending_refcount),
        .dbg_epoch_erased(dbg_epoch_erased)
    );

    always #5 clk = ~clk;

    task command;
        input [2:0] op;
        input [3:0] line;
        input [7:0] writer;
        input [1:0] slot;
        input [7:0] generation;
        input [2:0] epoch;
        input [31:0] ctr;
        begin
            @(negedge clk);
            req_valid = 1;
            req_op = op;
            req_line = line;
            req_writer = writer;
            req_slot = slot;
            req_generation = generation;
            req_epoch = epoch;
            req_ctr = ctr;
            @(negedge clk);
            req_valid = 0;
            if (!rsp_valid) begin
                $display("FAIL: missing response");
                $fatal(1);
            end
        end
    endtask

    task expect_status;
        input [2:0] expected;
        input [255:0] label;
        begin
            if (rsp_status !== expected) begin
                $display("FAIL: %0s expected status %0d got %0d",
                         label, expected, rsp_status);
                $fatal(1);
            end
        end
    endtask

    task reserve;
        input integer index;
        input [3:0] line;
        input [7:0] writer;
        begin
            command(OP_RESERVE, line, writer, 0, 0, 0, 0);
            expect_status(ST_OK, "reserve");
            slots[index] = rsp_slot;
            generations[index] = rsp_generation;
            epochs[index] = rsp_epoch;
            counters[index] = rsp_ctr;
        end
    endtask

    task use_token;
        input [2:0] op;
        input integer index;
        input [3:0] line;
        input [7:0] writer;
        begin
            command(op, line, writer, slots[index], generations[index],
                    epochs[index], counters[index]);
        end
    endtask

    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;

        reserve(0, 4'd5, 8'd1);
        reserve(1, 4'd5, 8'd2);
        reserve(2, 4'd5, 8'd3);
        if (!(counters[0] == 1 && counters[1] == 2 && counters[2] == 3)) begin
            $display("FAIL: atomic reservations were not unique");
            $fatal(1);
        end

        use_token(OP_ENCRYPT, 0, 4'd5, 8'd1);
        expect_status(ST_OK, "encrypt writer 1");
        use_token(OP_ENCRYPT, 1, 4'd5, 8'd2);
        expect_status(ST_OK, "encrypt writer 2");
        use_token(OP_ENCRYPT, 2, 4'd5, 8'd3);
        expect_status(ST_OK, "encrypt writer 3");

        use_token(OP_COMMIT, 2, 4'd5, 8'd3);
        expect_status(ST_OK, "newest commit");
        use_token(OP_COMMIT, 0, 4'd5, 8'd1);
        expect_status(ST_STALE, "late stale commit 1");
        use_token(OP_COMMIT, 1, 4'd5, 8'd2);
        expect_status(ST_STALE, "late stale commit 2");

        command(OP_TICKET, 4'd5, 0, 0, 0, 0, 0);
        expect_status(ST_OK, "ticket snapshot");
        if (!(rsp_epoch == 1 && rsp_ctr == 3 && rsp_writer == 3)) begin
            $display("FAIL: ticket did not return authoritative version");
            $fatal(1);
        end

        use_token(OP_COMMIT, 2, 4'd5, 8'd3);
        expect_status(ST_BAD_TOKEN, "consumed token replay");

        reserve(0, 4'd6, 8'd1);
        use_token(OP_ENCRYPT, 0, 4'd6, 8'd1);
        expect_status(ST_OK, "held reservation encryption");

        command(OP_ADVANCE, 0, 0, 0, 0, 0, 0);
        expect_status(ST_OK, "advance to epoch 2");
        reserve(1, 4'd5, 8'd2);
        use_token(OP_ENCRYPT, 1, 4'd5, 8'd2);
        use_token(OP_COMMIT, 1, 4'd5, 8'd2);
        expect_status(ST_OK, "migrate live line to epoch 2");
        command(OP_ADVANCE, 0, 0, 0, 0, 0, 0);
        expect_status(ST_OK, "advance to epoch 3");

        command(OP_REVOKE, 0, 0, 0, 0, 3'd1, 0);
        expect_status(ST_BLOCKED, "pending reservation blocks erase");
        use_token(OP_CANCEL, 0, 4'd6, 8'd1);
        expect_status(ST_OK, "lease expiry/cancel");
        command(OP_REVOKE, 0, 0, 0, 0, 3'd1, 0);
        expect_status(ST_OK, "erase after references drain");
        if (!dbg_epoch_erased) begin
            $display("FAIL: epoch erase state not recorded");
            $fatal(1);
        end

        use_token(OP_COMMIT, 0, 4'd6, 8'd1);
        expect_status(ST_BAD_TOKEN, "late commit after expiry");

        $display("PASS: EBFI metadata controller RTL regression");
        $finish;
    end
endmodule
