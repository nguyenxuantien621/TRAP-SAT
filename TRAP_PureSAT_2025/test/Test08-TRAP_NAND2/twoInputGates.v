// 2-input gates
// Date:        Oct 2022

module or2 (a,b,o);
    input a,b;
    output o;

    assign o = a || b;

endmodule

module and2 (a,b,o);
    input a,b;
    output o;

    assign o = a && b;

endmodule

module nand2 (a,b,o);
    input a,b;
    output o;

    assign o = ~(a && b);

endmodule

module xor2 (a,b,o);
    input a,b;
    output o;

    assign o = (a && ~b) || (~a && b);

endmodule
