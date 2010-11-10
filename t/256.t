use strict;
use warnings;
use Test::More tests => 68;
use Digest::Keccak qw(keccak_256 keccak_256_hex);

my $len = 0;

while (my $line = <DATA>) {
    chomp $line;
    my ($msg, $digest) = split '\|', $line, 2;
    my $data = pack 'H*', $msg;
    $digest = lc $digest;

    if ($len and not $len % 8) {
        my $md = Digest::Keccak->new(256)->add($data)->hexdigest;
        is($md, $digest, "new/add/hexdigest: $len bits of $msg");
        is(
            keccak_256_hex($data), $digest,
            "keccak_256_hex: $len bits of $msg"
        );
        ok(
            keccak_256($data) eq pack('H*', $digest),
            "keccak_256: $len bits of $msg"
        );
    }

    my $md = Digest::Keccak->new(256)->add_bits($data, $len)
        ->hexdigest;
    is($md, $digest, "new/add_bits/hexdigest: $msg");
}
continue { $len++ }

__DATA__
00|CEDDACF81DFBD0F45367E3EE10CAF61008E81F1B86D987A0B6F814197FCED240
00|E42415BF203845A6C58B4CE116C6C14523AA84E7CB3C9343A32CF243D71AC305
C0|F7B0FCC27CFAE6C20F8D572CC80F8298C0023B1F0A01628D271FF4F63B7436AB
C0|F2D7EB84D58569A4F51DBC966324F890689E7D379F9F98D59CD927C9CB2A0595
80|15AE393F8E6676FCD0CDE8A9E0E1CCD8878B606B5A3D4A66E8F536FDD13EED2B
48|ABEF5AA168B5654C2AB4C2E2A473F7A35AAE65168DB9101BF09E55C62B9EB44C
50|DFD44FB639714D3004D37EA084638434897236ADD3069AFA280973AB43B6CC23
98|F355913BCDFBFF19F935D47B13EAA8C57C90807166336E14D5D44771A75B8D5E
CC|5748B75AFE2F9FBB9C7AFE58C82DF81A5D439F0F605E6064D82F3ED926D2FB5E
9800|2927E281F37EFB4AF3BBE228CC47AE824A1074B2E75EB7DAA6A15604B57B1A2E
9D40|8819202E8D91E9EB4D3D85FC6B0F3545A3B34748C7A5EFA39341EE171240BE81
AA80|C29B03B9D1D1434C000235387B658A67CEF09877AD43698BDA1AD783BB2B168C
9830|DF6C893277DCBEE1E0D38198AF641626F96E5A47B91FD65248DF3451661B6EF4
5030|C79C7C2BF85D2358E354128C1D9742DA7090248CB775391D2A0760D36FF3EDFD
4D24|5E9520A36EEEB5A408E9B710943921B52E848C7B0B0427F620197C712FD85F4B
CBDE|3CD583557BDA691DE91CDE3F8A56C978C749DD97F3E70C85AB3F27AA020D5C6A
41FB|9E0CCCF1577E0F404EA02B4912014DFA381B970D5CA2D9E2C59E6C596B13DC1C
4FF400|B31100DC46B2E717241A545674738058D782E9895028D2C6B4938F6F12E591B1
FD0440|2E2B9DE2F42877AEC0651BCE514DF03C17398176FF26AFB1005BA547057DBCBF
424D00|9CFBDC0F39CF320840525419A2496F5FCE6B45C34C3CE704F31A05A2E8333467
3FDEE0|540357D28568A9FE1DC469FAF09469CC625A4EFF44CC939553C70869D521A7A3
335768|0D86F1EAC34928590258FA444EA909332C011DD10C73CF9956854F7E4DF9FE31
051E7C|A3D15F78C984C66AA5C5C64F248F949149BD76BEB15273382FB65A37264439F2
717F8C|BACB29679D332404ACE77E5229615F8B358C8084DACBE9F7DB9D710AEE574A69
1F877C|ECE6EDB4F27E36966CDCEFD371D551689062D3891C71E617167106D19C694AA8
EB35CF80|C7063804D2ED6535D7A1893B7464703705E8797EA5FF6EF24F273FA18B48DD60
B406C480|E7E827DD34ED5882F338B41B202913DAE254EFCD5EF1BA9D17387D04047CFA33
CEE88040|F5B05316E97A33394A3BD4ED3FABE16ABF3DD9FCD3CE1C61C4E788CAA57DA2F7
C584DB70|466C2700AE178D60632B3D6FA2C8C8CBC504C3F76920BAD7E39C04220BAAB916
53587BC8|B5329A680717EDA267347C90264BDD9F6B7454B66FD87396E4717267944F0EF7
69A305B0|2B81B54C1FC933AB9542A509A4D816CF93F34C81E9D71982092808CE07DE9FBF
C9375ECE|3EF09E2D27A118BA8BE1E6CE7347F537686F017A8FF509E5614B70306F931832
C1ECFDFC|EF0258F174B6A8BBC1C8CC344FCFAB48B133B89658E0908DA177C531D90D904C
8D73E8A280|0E57E25E4EC98F4F0B95696F93D64C937C01BBCFA09199D77EC50EC47FEC8DC6
06F2522080|27B31C28026591ECD9DA413433B6D66FD2F8456E7D29D91E5779DD7EF0EFFD94
3EF6C36F20|2A6AA52336187A1B74ACF93AAF6E2FF59E71A567A48DD9B4180C44E1FC19BD15
0127A1D340|E7CA6324790C8277D4C1A693AD2D30E62CA3FCE683DD3D300A614AF0AE62E1D9
6A6AB6C210|5FB8363ABB0B78318D8C62AA8D7B023D0C47B401EB4E954992A1125C41B14639
AF3175E160|394FE3B355637ADD89B467E575D7A42C6FAF37DEE8E66B78885D188C77233793
B66609ED86|5FD306C3B7BB585C40A32376DCF46E7A6BCA1006501FD7176EE4258E8C3DBA64
21F134AC57|8DB75C261124EE447D63937D89E3ACCA823C3FE3BF92F1DCD3A6C13B14397D48
3DC2AADFFC80|B096CFA697BD374C948ACE72750C5A013DB7CA97A38337366F795CC412FAAA19
9202736D2240|928B68264648BB9EF0BAD67BE5D6EB682B41B853A645EAB03DF86E64AFAF7390
F219BD629820|80A572F5A88A2C00824B703A18F31D4E1309F036F4DCBCAFD1DB675D0977186E
F3511EE2C4B0|9BA0ADA889EC080B381C0CE5AA80C7FDA1873160DDD2ADBFEE843EEFE31BA304
3ECAB6BF7720|D7C5547F75971E5FA7B8C08FD3AB6108BCE24B1A2D64EB6AD7DA928CE17E51C8
CD62F688F498|2CA40D16585260260B1DA9C31500D192B8004F7B8C72236C837A8A32F89AD70F
C2CBAA33A9F8|FFDB17FC9141178C9D97A2DBEC4BE7334E219C36229B775260F4D8C65A8E2ABF
C6F50BB74E29|075E137DEF0C69EB2A4B4244045B69E67CB8B73CF98164A0427D5352A2C340D4
79F1B4CCC62A00|9458A8FD7D06AF7626FCDF3F4734A6F4D8925755A40D46EB438A947D4C806232
