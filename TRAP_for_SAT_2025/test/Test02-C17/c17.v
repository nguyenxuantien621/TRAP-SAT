module c17 (pi1, pi2, pi3, pi6, pi7, po22, po23);
    input pi1, pi2, pi3;
    input pi6, pi7;
    output po22;
    output po23;

    wire pi10, pi11, pi16, pi19;

    nand nand1(pi10,pi1,pi3);
    nand nand2(pi11,pi3,pi6);
    nand nand6(pi16,pi2,pi11);
    nand nand5(pi19,pi11,pi7);
    nand nand3(po22,pi16,pi10);
    nand nand4(po23,pi16,pi19);

endmodule
