module Lab4_140L (
		  input wire   rst, // reset signal (active high)
		  input wire   clk,
		  input        bu_rx_data_rdy, // data from the uart is ready
		  input [7:0]  bu_rx_data, // data from the uart
		  output       L4_tx_data_rdy, // data ready to be sent to UART
		  output [7:0] L4_tx_data, // data to be sent to UART
		  output       L4_PrintBuf,
		  output [4:0] L4_led
		  );

   wire 	   sccDecrypt;    // processing a decrypt command
   wire 	   sccEncrypt;    // processing an encrypt command
   wire     sccEldByte;    // load a byte to encrypt
   wire     sccEmsBitsLd;  // load the msbits of the newly decrypted data
   wire     sccElsBitsLd;  // load the lsbits of the newly decrypted data
   wire 	   sccEmsBitsSl;  // select the ms bits of newly decrypted data
   wire 	   sccDnibble1En; // enable capture of the ms bits of encrypted data
   wire 	   sccDnibble2En; // enable capture of the ls bits of encrypted data
   wire 	   sccDByteValid; // decrypted byte is valid *not used*
   wire [7:0]      sccLdKey;      // load one of 8 key 4-bit registers
   wire 	   sccLdLFSR;     // load the LFSR from the key regsiter 
   wire 	   scdCharIsValid; // bu_rx_data is a printable character

   wire 	   de_validAscii;
   wire 	   de_bigD;
   wire 	   de_bigE;
   wire 	   de_bigL;
   wire 	   de_bigP;
   wire 	   de_bigS;
   wire 	   de_hex;
   wire 	   de_cr;
	wire     de_esc;

   scdp scdp (
	      .L4_tx_data(L4_tx_data),
	      .scdCharIsValid(scdCharIsValid),
	      .bu_rx_data(bu_rx_data),
	      .bu_rx_data_rdy(bu_rx_data_rdy),
	      .sccEncrypt(sccEncrypt),
	      .sccEldByte(sccEldByte),
	      .sccEmsBitsLd(sccEmsBitsLd),
	      .sccElsBitsLd(sccElsBitsLd),
	      .sccEmsBitsSl(sccEmsBitsSl),
	      .sccDecrypt(sccDecrypt),
	      .sccDnibble1En(sccDnibble1En),
	      .sccDnibble2En(sccDnibble2En),

	      .sccLdKey(sccLdKey),
	      .sccLdLFSR(sccLdLFSR),

	      .rst(rst),
	      .clk(clk)
	      );
   




   decodeKeysL4 dk (
		    .de_esc(de_esc),
		    .de_validAscii(de_validAscii),
		    .de_bigD(de_bigD),
		    .de_bigE(de_bigE),
		    .de_bigL(de_bigL),
		    .de_bigP(de_bigP),
		    .de_bigS(de_bigS),
		    .de_hex(de_hex),
		    .de_cr(de_cr),
		    .charData(bu_rx_data),
		    .charDataValid(bu_rx_data_rdy));

   scctrl ctrl (
		    .de_esc(de_esc),         
			 .de_validAscii(de_validAscii),  
			 .de_bigD(de_bigD),         
			 .de_bigE(de_bigE),         
			 .de_bigL(de_bigL),         
			 .de_bigP(de_bigP),         
			 .de_bigS(de_bigS),         
			 .de_hex(de_hex),          
			 .de_cr(de_cr),          
			 .scdCharIsValid(scdCharIsValid), 
			 .rst(rst),
			 .clk(clk),
			 .sccDecrypt(sccDecrypt),     
			 .sccEncrypt(sccEncrypt),    
			 .sccEldByte(sccEldByte),         	
			 .sccEmsBitsLd(sccEmsBitsLd),  
			 .sccElsBitsLd(sccElsBitsLd),  
			 .sccEmsBitsSl(sccEmsBitsSl),  	
			 .sccDnibble1En(sccDnibble1En), 
			 .sccDnibble2En(sccDnibble2En), 	
			 .sccDByteValid(sccDByteValid),   
			 .sccLdKey(sccLdKey),      
			 .sccLdLFSR(sccLdLFSR),     
			 .L4_tx_data_rdy(L4_tx_data_rdy),
			 .L4_PrintBuf(L4_PrintBuf),
			 .bu_rx_data_rdy(bu_rx_data_rdy),
			 .bu_rx_data(bu_rx_data));



endmodule

//
// scdp - stream cipher datapath
// refer to lab instructions for a block diagram
//
//
module scdp (
	     output [7:0] L4_tx_data,   //     data to be sent to uartTxBuf
	     output wire  scdCharIsValid, // encrypt byte is a valid character

	     input [7:0]  bu_rx_data,   // data from the uart
	     input 	  bu_rx_data_rdy, // data from the uart is valid this cycle 
	     input 	  sccEncrypt,   //     control signal indicating we are in encrypt mode
	     input 	  sccEldByte,   // control signal to load bu_rx_data into encrypt register
	     input 	  sccEmsBitsLd, // load the most significant 4 bits of encrypted data
	                                // as an 8-bit ascii hex number
	     input 	  sccElsBitsLd, // load the least significant 4 bits of encrypted data
	                                  // as an 8-bit ascii hex number
	     input 	  sccEmsBitsSl, // select the hex number for the most significant 4 bits
	                                  // of encrypted data to L4_tx_data
	     input 	  sccDecrypt, // we are in decrypt mode
	     input 	  sccDnibble1En, // load 4 bits of encrypted data (most significant)
	     input 	  sccDnibble2En, // load 4 bits of encryhptd data (least significant)
	     
	     input [7:0]  sccLdKey,      // load 4-bit (nibble) of the key
	     input 	  sccLdLFSR,     // load the LFSR from the key

	     input 	  rst,
	     input 	  clk
	     );


   
   wire [3:0] 		  binVal;               // conversion of ascii hex to bin

   wire [7:0] 		  psrByte;  // pseudo random byte


   asciiHex2Bin a2b (.val(binVal), .inVal(bu_rx_data));
   
   
   //
   // decrypt datapath
   //
   wire [7:0] 		  byteToDecrypt;        // byte we are decrypting
   regrce #(4) u0 (byteToDecrypt[7:4], binVal, sccDnibble1En, rst, clk);
   regrce #(4) u1 (byteToDecrypt[3:0], binVal, sccDnibble2En, rst, clk);
    
   wire [7:0] 		  e2dData;
   wire [7:0] 		  pCharDecrypt;   // printable char
   assign e2dData = byteToDecrypt ^ psrByte;
   printable pinst0 (.pChar(pCharDecrypt), .pValid(), .inByte(e2dData));

   

   //
   // encrypt data path
   //
   wire [7:0]		  byteToEncrypt;        // byte we are encrypting
   regrce #(8) u2 (byteToEncrypt, bu_rx_data, sccEldByte, rst, clk);
   
   printable pinst1 (.pChar(), .pValid(scdCharIsValid), .inByte(bu_rx_data));

   
   wire [7:0] 		  d2eData;
   
   assign d2eData = byteToEncrypt ^ psrByte;
   

   //
   // we are encrypting, convert 
   // to two hex digits
   // will send the digits over two cycles.  MS nibble followed by LS nibble.
   //
   wire [7:0] 		  msBitsD, msBits;
   wire [7:0] 		  lsBitsD, lsBits;
   
   bin2AsciiHex b2a0 (msBits, d2eData[7:4]);
   bin2AsciiHex b2a1 (lsBits, d2eData[3:0]);
   
   regrce #(8) msBitsi (msBitsD, msBits, sccEmsBitsLd, rst, clk);
   regrce #(8) lsBitsi (lsBitsD, lsBits, sccElsBitsLd, rst, clk);

   wire [7:0] 		  key0;// = 8'h78;// bits 7-0
   wire [7:0] 		  key1;// = 8'h56;// bits 15-8
   wire [7:0] 		  key2;// = 8'h34;// bits 23-16
   wire [7:0] 		  key3;// = 8'h12;// bits 31-24

   wire [3:0] 		 binValD;   // bu_rx_data delayed
   wire                  binVal_ValidD;
   regrce #(4) rxdataD (.q(binValD),
			.d(binVal),
			.ce(1'b1), .rst(rst), .clk(clk));
   regrce #(1) rddataDV (.q(binVal_ValidD), .d(bu_rx_data_rdy),
			 .ce(1'b1), .rst(rst), .clk(clk));
   
   regrce #(4) k0l (.q(key0[3:0]), .d(binValD),
		    .ce(sccLdKey[0] & binVal_ValidD),
		   .rst(rst), .clk(clk));
   regrce #(4) k0h (.q(key0[7:4]), .d(binValD),
		    .ce(sccLdKey[1] & binVal_ValidD),
		   .rst(rst), .clk(clk));
   regrce #(4) k1l (.q(key1[3:0]), .d(binValD),
		    .ce(sccLdKey[2] & binVal_ValidD),
		   .rst(rst), .clk(clk));
   regrce #(4) k1h (.q(key1[7:4]), .d(binValD),
		    .ce(sccLdKey[3] & binVal_ValidD),
		   .rst(rst), .clk(clk));
   regrce #(4) k2l (.q(key2[3:0]), .d(binValD),
		    .ce(sccLdKey[4] & binVal_ValidD),
		   .rst(rst), .clk(clk));
   regrce #(4) k2h (.q(key2[7:4]), .d(binValD),
		    .ce(sccLdKey[5] & binVal_ValidD),
		   .rst(rst), .clk(clk));
   regrce #(4) k3l (.q(key3[3:0]), .d(binValD),
		    .ce(sccLdKey[6] & binVal_ValidD),
		   .rst(rst), .clk(clk));
   regrce #(4) k3h (.q(key3[7:4]), .d(binValD),
		    .ce(sccLdKey[7] & binVal_ValidD),
		   .rst(rst), .clk(clk));



   wire [31:0] 		 lfsrVal;
   lfsr lfsrInst (
		  .lfsrVal(lfsrVal),
		  .psrByte(psrByte),
		  .ldVal({key3, key2, key1, key0}),
		  .ldLFSR(sccLdLFSR),
		  .step(sccDnibble2En | sccEldByte),
		  .rst(rst),
		  .clk(clk)
		  );
   

      
   assign L4_tx_data = sccEncrypt ?
		       (sccEmsBitsSl ? msBitsD : lsBitsD ) :
		       pCharDecrypt;
   
endmodule // scdp


//
// scctrl - stream cipher control
//
module scctrl ( 
	input    de_esc,          // esc key
	input    de_validAscii,   // valid ascii 0x20 to 0x7e
	input    de_bigD,         // "D"
	input    de_bigE,         // "E"
	input    de_bigL,         // "L"
	input    de_bigP,         // "P"
	input    de_bigS,         // "S"
	input    de_hex,          // 0-9a-f
	input    de_cr,           // carriage return
	input 	scdCharIsValid, // bu_rx_data is a printable character
   input    rst,
	input    clk,
	
   output  reg  sccDecrypt,    // processing a decrypt command  
   output  reg  sccEncrypt,    // processing an encrypt command 
   output  reg  sccEldByte,    // load a byte to encrypt       
	
   output  reg   sccEmsBitsLd,  // load the msbits of the newly decrypted data 
   output  reg   sccElsBitsLd,  // load the lsbits of the newly decrypted data
   output  reg	  sccEmsBitsSl,  // select the ms bits of newly decrypted data
	
   output  reg  sccDnibble1En, // enable capture of the ms bits of encrypted data 
   output  reg  sccDnibble2En, // enable capture of the ls bits of encrypted data 
	
   output  reg	  sccDByteValid, // decrypted byte is valid *not used*   
   output  reg [7:0]      sccLdKey,      // load one of 8 key 4-bit registers 
   output  reg  sccLdLFSR,     // load the LFSR from the key regsiter 
	output     L4_tx_data_rdy,
	output     L4_PrintBuf,
	input    bu_rx_data_rdy,
	
	input[7:0] bu_rx_data);
	
	
	
	
	reg rdy1, rdy2, buf1, buf2;
	reg printBufD;
	reg printBufE;
	reg printBufL;

	

	reg [3:0] cLState, nLState;
	parameter [3:0] loadStart=4'b0000, processLoad=4'b0001, key1=4'b0010, key2=4'b0011, key3=4'b0100, key4 = 4'b0101, 
	key5 = 4'b0110, key6 = 4'b0111, key7 = 4'b1000, key8=4'b1001, lfsrState = 4'b1010;  
	
	// loadKey
	always @(posedge clk) begin
		if (rst ) begin
			cLState <= loadStart;
		end
		else begin
			cLState <= nLState;
		end
	end
	
	always @(*)begin
		printBufL = 0;
		sccLdLFSR = 0;
		sccLdKey = 8'b00000000;
		
		case(cLState)
			loadStart:begin
			
				if(de_bigL)begin
					nLState=processLoad;
					
				end
				else begin
					nLState = loadStart;
					
				end
			
			end
			processLoad:begin
				if(de_hex)begin
					nLState=key1;
					sccLdKey = 8'b10000000;
					//sccLdKey = 8'b10000000;
				end
				else begin
				  nLState = processLoad;
				  sccLdKey = 8'b00000000; ///#############
				  
				end
			end
			
			key1: begin
				if(de_hex)begin
					nLState=key2;
					sccLdKey = 8'b01000000;
				//	sccLdKey = 8'b01000000;
				end
				else begin
				  nLState = key1;
				 // sccLdKey = 8'b00000000; //###
				  sccLdKey = 8'b10000000;//###
				end
			
			end
			
			key2: begin
				if(de_hex)begin
					nLState=key3;
					sccLdKey = 8'b00100000;
					//sccLdKey = 8'b00100000;
					
					
				end
				else begin
				  nLState = key2;
				  //sccLdKey =  8'b00000001;
				  sccLdKey = 8'b01000000;
				end
			
			end
			
			key3: begin
				if(de_hex)begin
					nLState=key4;
					//sccLdKey = 8'b00000100;
					sccLdKey = 8'b00010000;
				end
				else begin
				  nLState = key3;
				  //sccLdKey =8'b00000010;
				  sccLdKey = 8'b00100000;
				end
			
			end
			
			key4: begin
			   if(de_hex)begin
					nLState=key5;
					//sccLdKey = 8'b00001000;
					sccLdKey = 8'b00001000;
				end
				else begin
				  nLState = key4;
				  //sccLdKey =  8'b00000100;
				  sccLdKey = 8'b00010000;
				end
			
			end
			
			key5: begin
				if(de_hex)begin
					nLState=key6;
					//sccLdKey = 8'b00010000;
					sccLdKey = 8'b00000100;
				end
				else begin
				  nLState = key5;
				  //sccLdKey =  8'b00001000;
				  sccLdKey = 8'b00001000;
				end
			
			end
			
			key6: begin
				if(de_hex)begin
					nLState=key7;
					//sccLdKey = 8'b00100000;
					sccLdKey = 8'b00000010;
				end
				else begin
				  nLState = key6;
				  //sccLdKey =8'b00010000;
				  sccLdKey = 8'b00000100;
				end
			
			end
			
			key7: begin
				if(de_hex)begin
					nLState=key8;
					//sccLdKey = 8'b01000000;
					sccLdKey = 8'b00000001;
					
				end
				else begin
				  nLState = key7;
				  //sccLdKey = 8'b00100000;
				  sccLdKey = 8'b00000010;
				  
				end
			
			end
			
			key8: begin
				if(de_cr)begin
					nLState=lfsrState;
					sccLdKey = 8'b00000000;//###########
					
					printBufL = 1;
				
				end
				else begin
				  nLState = key8;
		// sccLdKey = 8'b01000000;
				 sccLdKey = 8'b00000001;
				  
				end
			end
			
			lfsrState: begin
			 
			    nLState = loadStart;
				 sccLdLFSR = 1;
				// sccLdKey = 8'b10000000;
				 

			end
			
			
			default: begin
			     nLState = loadStart;
				  			
			end
		 	  
		
		endcase
	end
	
	
	
	/// encrypt
	reg [2:0] cEState, nEState;
	parameter [2:0] encryptStart=3'b0, encrypt=3'b001, processE=3'b010, msE=3'b011, lsE=3'b100, printState = 3'b101;  
	
	always @(posedge clk) begin
		if (rst | de_cr) begin
			cEState <= encryptStart;
		end
		else begin
			cEState <= nEState;
		end
	end
	
	always @(*)begin
			sccEncrypt=1'b0;
			sccEldByte=1'b0;
			sccEmsBitsLd=1'b0;
			sccElsBitsLd=1'b0;
			sccEmsBitsSl=1'b0;
			rdy1=1'b0;
			printBufE=1'b0; //################
			
		case(cEState)
		encryptStart: begin
			if(de_bigE) begin
				nEState=encrypt;
				
				sccEncrypt=1'b1;
	
			end
			else begin
			  nEState = encryptStart;
			  
			end
		
		 end
		 
		 encrypt: begin
			if(de_validAscii) begin
		
				nEState=processE;
				sccEldByte=1'b1;
				sccEncrypt=1'b1;
			
			end
			else if (de_cr) begin
			   nEState = encryptStart;
				printBufE = 1;
			
			end
			else begin
			   nEState = encrypt;
			end
		 
		 end
		 
		 processE: begin
			nEState=msE;
			sccEmsBitsLd=1'b1; //[7:4]=1
			sccEncrypt=1'b1;
			sccElsBitsLd=1'b1; // sccElsBitsLd=1'b0;

		 end
		 
		 msE: begin
			nEState=lsE; 
			sccEncrypt=1'b1;
			sccEmsBitsSl=1'b1; //sccEmsBitsSl=1'b0;
			rdy1=1'b1;  
			
			
		 end
	
		
		 
		 lsE:begin
			nEState=printState;
			sccEncrypt=1'b1;
			//sccElsBitsLd=1'b0;
			rdy1=1'b1; 
			//printBufE = 1;
			
		 end
		 
		 printState: begin
		    nEState = encrypt;
			 sccEncrypt = 1;
			 //printBufE = 1;
		 end
		 

		 
		default: begin
			nEState=encryptStart; 
		
		end
		
		endcase
	end
	
	//assign L4_tx_data_rdy = sccEncrypt? rdy1 : (sccDecrypt? rdy2 : 1'b0);
	//assign L4_PrintBuf = sccEncrypt? buf1 : (sccDecrypt? buf2 : 1'b0);
	
	
	/// decrypt
	reg [2:0] cDState, nDState;
	parameter [2:0] decryptStart=3'b000, decrypt=3'b001, msD=3'b010, lsD = 3'b011;
	
		always @(posedge clk) begin
			if (rst | de_cr) begin
				cDState <= decryptStart;
			end
			else begin
				cDState <= nDState;
			end
		end
		always @(*)begin	
					printBufD = 0;
					sccDnibble1En=1'b0; 
					sccDecrypt=1'b0;
					sccDnibble2En=1'b0;
					sccDByteValid=1'b0;
					rdy2=1'b0; 
		case(cDState)
			decryptStart: begin
				if(de_bigD) begin
					nDState=decrypt;
					sccDecrypt=1'b1;
				
				end
				else begin
					nDState = decryptStart;
				
				end
			end
			
			decrypt:begin
				if(de_hex)begin
					
					nDState=msD;
					sccDnibble1En=1'b1; 
					sccDecrypt=1'b1;
				
				end
				else if(de_cr) begin
				   nDState = decryptStart;
					printBufD = 1; //################################## may not be here
				
				end
				
			
				else begin
				   nDState = decrypt;
					
					end
			end
			
			msD:begin
			   if(de_hex) begin
				   nDState = lsD;
				   sccDecrypt = 1;
				   sccDnibble2En=1'b1;
				
				end
				
				else begin
				  nDState = msD;
				   
				end
			
			end
			
			lsD: begin
			   rdy2 = 1;
				nDState = decrypt;
			
			end
			
			
		 
			default:begin
				nDState=decryptStart;	

			end
		
		endcase
	end
	
	assign L4_PrintBuf = printBufD | printBufE | printBufL ; ///##################
	assign L4_tx_data_rdy = rdy1 | rdy2;
	
	


endmodule // scctrl

