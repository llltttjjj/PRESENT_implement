# PRESENT_implement

This is a code presentation for PRESENT implementation as a appendix for my bachelor thesis.

If you use Visual Studio, it should be easy for you to test this code by yourself. Both LLVM and MSVC compilers are supported by this code. I haven't tested compiling with GCC by now.

As an example, here is a output of this program:

Testing the original implement 10000000 times.
Performance: 1764.99 CPB
The output is: 0DCD1CFE570172B7
Costs 61284 ms.

Testing the implement with new lookup table 10000000 times.
Performance: 35.1545 CPB
The output is: 0DCD1CFE570172B7
Costs 1221 ms.

Testing the implement with bit-slicing to encrypt 64 different plaintext 10000000 times.
Performance: 23.4933 CPB
Costs 52207 ms.
The output is:
0x00: 0DCD1CFE570172B7|0x01: 4F0242D6110A0DE6|0x02: C8D6B29F1859DAA4|0x03: 3037B10EAD36F774|0x04: 049E8CC95AC61B6F|0x05: CA54C8AD0CDFF663|0x06: B28D7A65E7AB5846|0x07: 411C399F3DDD695E
0x08: 502FB09189D153F7|0x09: A97C8C0D68129044|0x0A: 53EE06F4948E8F3B|0x0B: 25C0C9D080A9794B|0x0C: 71CB43592DBC1314|0x0D: AEF1155E034DB496|0x0E: 35F8F17E4EAD78E1|0x0F: B120738D00DD91B2
0x10: 22C0B6C5867BA875|0x11: FB3CE05D1303B716|0x12: 0691DBC7E5555F29|0x13: FF87BDA8CF9AB571|0x14: 8182D868550A4181|0x15: 664A363DB4CE918A|0x16: 67629CA2AC7BA3CE|0x17: 8AADA989BA402D77
0x18: A6DA974A9C5C52A6|0x19: 1554E5009A1149C3|0x1A: 9AA9270325DE6F16|0x1B: 262410570DFFA1C2|0x1C: 57118C1E2BAE44B0|0x1D: AD1670086EF4CB49|0x1E: B2B912B880151C32|0x1F: E8BFA8197B068CA2
0x20: 12D1778865570D16|0x21: EC9077F3836620A4|0x22: 23FAE3AF46D53DDC|0x23: 6D29DC86CAC9A67B|0x24: AC07312D9BBA9E18|0x25: 3BD4EFFF08DD7F9A|0x26: E85168E292E6B9F3|0x27: A219D8B740B7F5CD
0x28: 3B80C131E3A3BC93|0x29: C7FDEF1DC0D21D0F|0x2A: 35FB7EFE91A15840|0x2B: 989C4CC065D34918|0x2C: EF6E0BCE3A981933|0x2D: BE2DBA7042841364|0x2E: 6FDE99495A8372FF|0x2F: 80FD23DF9B5A6747
0x30: 07457E25F5AC6019|0x31: 21F9CA3A018AB296|0x32: 00C8369DAF3DDA06|0x33: 88037B1DD3AA84EA|0x34: ABF0D97B8FDC0358|0x35: 3B5C0CBA0817620B|0x36: B9886ABACA05889B|0x37: A9FA757E56915938
0x38: 6104E6447ED5B196|0x39: 7793E7BFFAE26E94|0x3A: F83238913D8F61AB|0x3B: 5E18359C7E823DF6|0x3C: 3239EA8F083A295B|0x3D: A630B176C83E3265|0x3E: CCB6E190FC4267AF|0x3F: 14333F2F44A9958C

Testing the implement with new lookup table to encrypt 64 different plaintext 10000000 times.
Performance: 35.1915 CPB
Costs 78203 ms.
The output is:
0x00: 0DCD1CFE570172B7|0x01: 4F0242D6110A0DE6|0x02: C8D6B29F1859DAA4|0x03: 3037B10EAD36F774|0x04: 049E8CC95AC61B6F|0x05: CA54C8AD0CDFF663|0x06: B28D7A65E7AB5846|0x07: 411C399F3DDD695E
0x08: 502FB09189D153F7|0x09: A97C8C0D68129044|0x0A: 53EE06F4948E8F3B|0x0B: 25C0C9D080A9794B|0x0C: 71CB43592DBC1314|0x0D: AEF1155E034DB496|0x0E: 35F8F17E4EAD78E1|0x0F: B120738D00DD91B2
0x10: 22C0B6C5867BA875|0x11: FB3CE05D1303B716|0x12: 0691DBC7E5555F29|0x13: FF87BDA8CF9AB571|0x14: 8182D868550A4181|0x15: 664A363DB4CE918A|0x16: 67629CA2AC7BA3CE|0x17: 8AADA989BA402D77
0x18: A6DA974A9C5C52A6|0x19: 1554E5009A1149C3|0x1A: 9AA9270325DE6F16|0x1B: 262410570DFFA1C2|0x1C: 57118C1E2BAE44B0|0x1D: AD1670086EF4CB49|0x1E: B2B912B880151C32|0x1F: E8BFA8197B068CA2
0x20: 12D1778865570D16|0x21: EC9077F3836620A4|0x22: 23FAE3AF46D53DDC|0x23: 6D29DC86CAC9A67B|0x24: AC07312D9BBA9E18|0x25: 3BD4EFFF08DD7F9A|0x26: E85168E292E6B9F3|0x27: A219D8B740B7F5CD
0x28: 3B80C131E3A3BC93|0x29: C7FDEF1DC0D21D0F|0x2A: 35FB7EFE91A15840|0x2B: 989C4CC065D34918|0x2C: EF6E0BCE3A981933|0x2D: BE2DBA7042841364|0x2E: 6FDE99495A8372FF|0x2F: 80FD23DF9B5A6747
0x30: 07457E25F5AC6019|0x31: 21F9CA3A018AB296|0x32: 00C8369DAF3DDA06|0x33: 88037B1DD3AA84EA|0x34: ABF0D97B8FDC0358|0x35: 3B5C0CBA0817620B|0x36: B9886ABACA05889B|0x37: A9FA757E56915938
0x38: 6104E6447ED5B196|0x39: 7793E7BFFAE26E94|0x3A: F83238913D8F61AB|0x3B: 5E18359C7E823DF6|0x3C: 3239EA8F083A295B|0x3D: A630B176C83E3265|0x3E: CCB6E190FC4267AF|0x3F: 14333F2F44A9958C
