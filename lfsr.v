module lfsr (
	     output reg [31:0] lfsrVal, // lfsr current value
	     output reg [7:0]  psrByte, // psuedo random byte
	     input [31:0]  ldVal, //  load value to LFSR
             input 	   ldLFSR, // load the LFSR, up to 32 bits
             input 	   step,    // advance the LFSR 
	     input 	   rst,
	     input 	   clk);
		  
	
//		  reg onehot;
//		  reg [29:0] shift;
		  reg [31:0] lfsrval_next;
		 
		  reg  t_lfsrVal;

		  
		  always @(posedge clk or posedge rst) 
		  begin
		    if (rst) begin
			   
				  lfsrVal[31:0] <= 32'h00000000;
			 end
			
			 
			 else if (ldLFSR) begin
			    lfsrVal <= ldVal;
			  end
			  
			 else begin
			    lfsrVal <= lfsrval_next;
				
			 end
			 end
			 
			 always @ * begin 
		
			   t_lfsrVal = (lfsrVal[30] ^  lfsrVal[12] ^ lfsrVal[6] ^ lfsrVal[5] ^  lfsrVal[2]);
				if(step)
				  lfsrval_next[31:0] = {lfsrVal[30:0], t_lfsrVal};
				else 
				  lfsrval_next = lfsrVal;
			 
			
			
			  psrByte[7:0] = (lfsrVal[7:0] ^  lfsrVal[15:8] ^ lfsrVal[23:16] ^ {1'b1,  lfsrVal[30:24]});
			  // psrByte[7:0] = 0;
			 
		  
		  
		  end

endmodule // lfsr
