//mit license.
//thanks pedro oval & strife onizuka for other hmac-sha1's in lsl that inspired this.
//thanks to H. Krawczyk & R. Canetti of IBM and M. Bellare of UCSD for RFC 2104's "implementation note" (p. 3)
//   "These intermediate results are stored and then used to
//   initialize the IV of H each time that a message needs to be
//   authenticated." 
//this version of hmac-sha1 is faster than preceding LSL implementations due to heeding the above advice!
//~gistya~ 2014
//this came from:
//https://github.com/gistya/LSL-HMAC-SHA1-Fast

string K; //length = 40 GET FROM READER SCRIPT/NOTECARD
string K64;
integer g_BLOCKSIZE = 64;     
list comp; 
integer v8 = 0x80000000;

integer notecardLine = 0;
string notecardName = "Setup";
integer dataLine;
list noteCardList; 
key notecardQueryId; 

string sign(string request) {
    return hx264u(hm64c(llStringToBase64(request)));
}

//HMAC-SHA1:

string hexc="0123456789ABCDEF";
string hx264u(string a) {
    integer i = 0; integer len = llStringLength(a += "0000") - 4; string res = "";
    while (i < len) {
        res += llGetSubString(llIntegerToBase64(4*(integer)("0x" + llGetSubString(a, i, i+5))), 1, 4);
        i += 6; }
    return llGetSubString(res, 0, len*2/3);
}
string unpad(string b64) { 
    integer i; do ; while(llGetSubString(b64, i = ~-i, i) == "=");
    return llGetSubString(b64, 0, i);
}
list b6hm4comp(string b64, integer H1, integer H2, integer H3, integer H4, integer H5, integer i) {
    integer A = H1; integer B = H2; integer C = H3; integer D = H4;
    integer E = H5; integer round; integer S = 0; integer T; list x = []; string buf;
    do { T = llBase64ToInteger(buf = llGetSubString(b64, T = ((i + round) << 4) / 3, T+6)) << (S = ((i + round) % 3) << 1);
        if(S) T = T | (llBase64ToInteger("A" + (llDeleteSubString(buf, 0, 1))) >> (6 - S));
        x += T; T += ((A << 5) | ((A >> 27) & 0x1F)) + (D ^ (B & (C ^ D))) + E + 0x5a827999;
        E = D; D = C; C = ((B << 30) | ((B >> 2) & 0x3FFFFFFF)); B = A; A = T;
    }while(16 > (round = -~round));
    do { S = llList2Integer(x,  -3) ^ llList2Integer(x,  -8) ^ llList2Integer(x, -14) ^ llList2Integer(x, -16);
        x = llList2List(x + (T = ((S << 1) | !!(S & v8))), -16, -1);
        T += ((A << 5) | ((A >> 27) & 0x1F)) + (D ^ (B & (C ^ D))) + E + 0x5a827999;
        E = D; D = C; C = ((B << 30) | ((B >> 2) & 0x3FFFFFFF)); B = A; A = T;
    }while(20 > (round = -~round));
    do { S = llList2Integer(x,  -3) ^ llList2Integer(x,  -8) ^ llList2Integer(x, -14) ^ llList2Integer(x, -16);
        x = llList2List(x + (T = ((S << 1) | !!(S & v8))), -16, -1);
        T += ((A << 5) | ((A >> 27) & 0x1F)) + (B ^ C ^ D) + E + 0x6ed9eba1;
        E = D;  D = C; C = ((B << 30) | ((B >> 2) & 0x3FFFFFFF)); B = A; A = T;
    }while(40 > (round = -~round));
    do { S = llList2Integer(x,  -3) ^ llList2Integer(x,  -8) ^ llList2Integer(x, -14) ^ llList2Integer(x, -16);
        x = llList2List(x + (T = ((S << 1) | !!(S & v8))), -16, -1);
        T += ((A << 5) | ((A >> 27) & 0x1F)) + ((B & C) | (B & D) | (C & D)) + E + 0x8f1bbcdc;
        E = D; D = C; C = ((B << 30) | ((B >> 2) & 0x3FFFFFFF)); B = A; A = T;
    }while(60 > (round = -~round));
    do { S = llList2Integer(x,  -3) ^ llList2Integer(x,  -8) ^ llList2Integer(x, -14) ^ llList2Integer(x, -16);
        x = llList2List(x + (T = ((S << 1) | !!(S & v8))), -16, -1);
        T += ((A << 5) | ((A >> 27) & 0x1F)) + (B ^ C ^ D) + E + 0xca62c1d6;
        E = D; D = C; C = ((B << 30) | ((B >> 2) & 0x3FFFFFFF)); B = A; A = T;
    }while(80 > (round = -~round)); return [H1+A, H2+B, H3+C, H4+D, H5+E]; 
} 
string b6hm4c(string b64, integer bit_length, integer extra_bit_length, integer H1, integer H2, integer H3, integer H4, integer H5) {
    integer b = ((bit_length + 40) >> 5) | 15;
    integer T = llBase64ToInteger(unpad(llGetSubString(b64, -4, -1)) + "AAAA");
    string buf = "AAA";
    integer i = -5;
    do buf += buf; while((i = -~i));
    if(bit_length) {
        i = 0x800000;
        if(!(bit_length % 24)) i = 0x80;
        else if((bit_length % 24) == 16) i = 0x8000;
    }
    else T = v8;
    bit_length += extra_bit_length;
    b64 = llGetSubString( llDeleteSubString(b64, -4, -1) + 
                          llGetSubString(llIntegerToBase64(T | i), 0, 5) + 
                          buf, 0, (b << 4) / 3) + llIntegerToBase64(bit_length << (6 - ((b % 3) << 1)));
    list x; i = 0;
    do {x = b6hm4comp(b64, H1, H2, H3, H4, H5, i);
        H1 = llList2Integer(x, 0);
        H2 = llList2Integer(x, 1);
        H3 = llList2Integer(x, 2);
        H4 = llList2Integer(x, 3);
        H5 = llList2Integer(x, 4);
    }while(b > (i += 16));
    x = [H1, H2, H3, H4, H5];
    i = -5;
    buf = "";
    do {T = llList2Integer(x,i);
        bit_length = 32;
        do buf += llGetSubString(hexc, b = ((T >> (bit_length -= 4)) & 0xF), b);
        while (bit_length);
    }while ((i = -~i));
    return buf;
}
string hm64c(string B64Data) {
    integer bit_length = (6 * !(B64Data=="") * (llStringLength(B64Data)-4+llStringLength(unpad(llGetSubString(B64Data,-4,-1))))) & -8;
    B64Data = hx264u(b6hm4c(B64Data, bit_length, 512, llList2Integer(comp, 0), llList2Integer(comp, 1), llList2Integer(comp, 2), llList2Integer(comp, 3), llList2Integer(comp, 4))) + "=";
    string K64o = llXorBase64StringsCorrect(K64, "ampqampqampqampqampqampqampqampqampqampqampqampqampqampqampqampqampqampqampqampqampqag==");
    list comp2 = b6hm4comp(K64o, 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0);
    bit_length = 160;
    return b6hm4c(B64Data, bit_length, 512, llList2Integer(comp2, 0), llList2Integer(comp2, 1), llList2Integer(comp2, 2), llList2Integer(comp2, 3), llList2Integer(comp2, 4));
}
init_pads() { 
    K64 = llStringToBase64(K);
    integer bit_length = llSubStringIndex(K64, "=");
    if (!~bit_length) {
        bit_length = llStringLength(K64);
    }
    if (bit_length > 86) {
        K64 = hx264u(b6hm4c(K64, (bit_length*6)&-8, 0, 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0));
        bit_length = 27;
    }
    K64 = llGetSubString(K64, 0, bit_length-1);
    string buf = "AAA";
    integer i = -5;
    do buf += buf; while((i = -~i));
    K64 = llXorBase64StringsCorrect(llGetSubString(K64 + buf, 0, 85) + "==", "NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2Ng==");
    comp = b6hm4comp(K64, 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0);
}

default {
    state_entry() {    
        notecardLine = 0;
        integer x = llGetInventoryType(notecardName);
        if(x==INVENTORY_NONE) state exception;
        else notecardQueryId = llGetNotecardLine(notecardName, 0); 
    }
    
    dataserver(key query_id, string data) {
        if (query_id == notecardQueryId) {
            if (data == EOF) {
                    if(K == "")
                        state exception;
                else { 
                    init_pads();
                    llOwnerSay("Initialization complete. Free memory: " +(string)llGetFreeMemory());
                }
            } else {
                integer x;
                if(llGetSubString(data,0,1) != "//") { 
                    if(llToLower(llGetSubString(data,0,4))=="pkey=") A = llGetSubString(data,5,-1);
                    else if(llToLower(llGetSubString(data,0,4))=="skey=") K = llGetSubString(data,5,-1);
                    ++dataLine;
                }
                ++notecardLine;
                notecardQueryId = llGetNotecardLine(notecardName, notecardLine);
            }
        } 
    }
    
    //here implement a link message event (or whatever) to link this up with your own code
}
 
state exception {
    
    state_entry() {
        llSay(0,"Notecard configuration error. Please ensure notecard named \"Setup\" is present, and contains one line with "skey=YOURSECRETKEYHERE" configured. See readme on github for details. Please reset the script manually.");
    }

}
