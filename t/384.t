use strict;
use warnings;
use Test::More tests => 19;
use Digest::Keccak qw(keccak_384 keccak_384_hex);

my $len = 0;

while (my $line = <DATA>) {
    chomp $line;
    my ($msg, $digest) = split '\|', $line, 2;
    my $data = pack 'H*', $msg;
    $digest = lc $digest;

    if ($len and not $len % 8) {
        my $md = Digest::Keccak->new(384)->add($data)->hexdigest;
        is($md, $digest, "new/add/hexdigest: $len bits of $msg");
        is(
            keccak_384_hex($data), $digest,
            "keccak_384_hex: $len bits of $msg"
        );
        ok(
            keccak_384($data) eq pack('H*', $digest),
            "keccak_384: $len bits of $msg"
        );
    }
    else {
        TODO:
        eval {
            local $TODO = 'add_bits is not yet implemented';
            my $md = Digest::Keccak->new(384)->add_bits($data, $len)
                ->hexdigest;
            is($md, $digest, "new/add_bits/hexdigest: $msg");
        };
    }
}
continue { $len++ }

__DATA__
00|098345C2DD7B57AF074284D4FF17CC3EBF0B5A84CB647D3323F01DC5B3DE62FF9957B800E845FCD904D869CC5AB3005E
00|0F4B58C1355DC8912B32F8ECCD3326A18026F209770D8E3E5C7F42E71BD6261C6C23A5C7A508644A23F548B555066045
C0|681E567F6E5F4272A130192B6C4E738AC79B30B35301850424A33232BBBCEA9A6D12FE8DB4664A092712030FFD44A848
C0|875C103D23B1950873EA97E71F1D4F8AD70BB59C87096718C197D61A088CB51A4D4AA02EF970A3CDA4FF9A9BE601ADED
80|841755034E92E45EAFD505457841B86BDD1C4686C8AC7EBB8D9347C0AC689141AD39758D0EE3BF2A1578341961C895CE
48|E152EBBFA9B6A4A578271628982C0315F4CE4AF82D5D7F92360CE40424BE061CC210687CA8E6F0E230DE49DA08D58DA4
50|131783CC362696F1D0E4C0A90D18F4942BB83D8487F269710BB86A98FEA364C2B43FB7DA97AE41A5569C07E98C1B71F9
98|D11C73EF8136BBAEE099FD94ED334D5807AA2F02DAB8595881999201444F83CD2E24D58601AB71554B526E3838769F66
CC|0C127AF997D649875583DBA6F6EA9B419C5D66725E28252189D0DAC06CB76C9F84C1273462B1676D6EC1AE299FC3F393
9800|DC5C96F4D4035DC52B5AC46C0E735D7DC8336251EA0EFD9E7D7FC6207DAC4902CEC94622570166005068CEF63C1ECD75
9D40|D6956B9F7C17D42A00EF57C29D0DC378905FD1D213AD5808E8335D0AA6581F654B506FDAFF1027CE5D357CFC63ABF504
AA80|59E17A933EB041765CA80F9DCA8B6BDF3869F5628DCB81EF4E4C91E15C9BDF279BF7BCF6FB37D428B207F483037AAB16
9830|8B1479DC7D45E616FED74FD2DEBD1893AEB36E52B8F6D9BE83C603583DC5E10D14DB7A0EA60E27F9EA7C1F7D0F9898F9
5030|6954FA2AA85464202353A14E93DEAC4AA7EB51C5EE724762D09B93340AE26D0CD5D5B52E456D77F1154922F25B0527A2
4D24|66112C136ABAB913A202D38D1A64A0D5BE482A7E3089A869A55B4FB85D4EB621D1F74284A7599C6F8EB33D5DE217201D
CBDE|452F6C96FB0D865848166607B11246CE07D15D27B253917B6D3AE5DC01B9701AA6BA9C972CED25A17AD2C6671F632A2F
41FB|5D7C16F1D518DD0EC4D061A115C17121984CE652498811D1DB9364A5B08ABE459C1718914D5A8E53AA7E49E41C71AA33
4FF400|DF29BFCD3B78365EBC72023D222A98034A910D1346422BCB7C3C473A34CA9E80F223F7536DBC96F6A549DA0720638A1B
FD0440|B0C8BA912E665CD3259AE6BA2CD7A4494E2328D95CC06EA2E7A0859AE84F2BB99EB526CC6243D0D078083AE90CCDCF8C
424D00|EF0F0BB2305C2F14FE7E95FC4694A88C7C702CC789AB900E69DCF454B72E4EE90709AE17D44C12B28D97F1C6D4980DF2
3FDEE0|F216F295443EA1B2EAB8BC10227EDB905BC89CFA1ADB4BC3E41EC4CDAEDED4568220867835C73E98FB6A687A8A87969D
335768|C42F6F6695C71185EDBA8160EEF0F95BA904020CC475CC0D1BA19A3334812F5909AFA78DE1FA9A9308C0F154B2EF9446
051E7C|5D995229AB07E57BA5EF0E0B2BE243157957068BA83AE00191EA7C09B7A7778EE29568AA3F0692A3E83823E6809CB94A
717F8C|942A46642DCD0A53343C1B0EE07452BEFB55B66C96505A931105C68AE2CF9E79650D75A4121BCD1C72D80A3CAB3FA804
1F877C|70AC54D96592EFC02BF79AA8E9496A58E7952603441B6DD2F9CBBA39CC6611958A2E2B2C27E887FAC47926F432628675
EB35CF80|6B834CB2FC74C2344015E75729BBCE5A9359364653535C490889C857427F09DC850D7079BDC18478A02505E39AEB3728
B406C480|06DC38885FD4E994BEB24BF0AEFF0CBF9F2FDB864F83E0E48716C02C4C9BEA2A7E3BBF461604CE1E894E0D426637D7B4
CEE88040|A47F3A30539C98A1EEF29CD5B963633A5C515A3DBB9C85D530C790F5E7727DA933A23A54FDBAC6FB7901CD72FB5A7C2C
C584DB70|E3207EE599EACF49791C660E632553BEB7978902FB45E4281FD7411CE5450F4E1C1E100763539D63021FC90475CC42FE
53587BC8|25B2A06A93EBA755BDB718333D5896EEF25628C11B0DB9E76CBCF141C628B40A8F7757E4AB9011B9CEBDE2C955882E38
69A305B0|38ABAFF769BF94E5A1324470BC8D0511C5088AFDA2A8510E0549FA70CF0E166846439C8FDC5A8061C675F297A193BB63
C9375ECE|4A999F80C4BAA1B215D50E1D8525CC29212901C95EC940DEBB1DAF8BBF37F668929708F8C8928D5FE6BBFEDFEDE9CBDE
C1ECFDFC|BA541D253622FFDEBB86A224989B53B7F31DE67C1BA6A0E129C72E83879838E41A813D413AA38147A6FDE490B152D5FA
8D73E8A280|5E37CCB4F2642929B7894F5F933AE88950E079931B994BA9BF8EEEDBAC1DE66D5460BF6720D6672D78EDEFC9066F9DB1
06F2522080|F33F953EDC8C9D869F14FF5CC41347FC73F7298FF900049CC8C5C6734D58C625785846CA619538E5ABC8954069B3C65F
3EF6C36F20|268EAB33BE3E7B42C2D186227D21E78866BD82842EB3CAE05E1E4E5A86C7A78E5DE924A60FD78421758D9B8DB28ECBD9
0127A1D340|504FA9439373C156A34086F4B7784F16CD96B0ABD139F36A00EA392A86FBD6494EA51CCAE22BDBD450BE319C246F50C3
6A6AB6C210|51B3E449DB54F006BC74B1B7EDA196E8DFA4ED6C3B75424DA43D4BE345AF555C23B37C363AE6091F42658BE7D6CCBD6F
AF3175E160|746A1DD7E81D76FD2909705298F54A7F5E788856F00D6FCE042634AF97C2F45C6EDE7ABF95222BEA0BBE6BD6A72E619C
B66609ED86|DAE407C7BBF20140712B1E83F80E314D3DFA4399BA018D64E9F88B087BC2854283B143E4869CDC6ADC58B5458B33368E
21F134AC57|CC97205D2BF3E92E8C36AD1BD83B16342D1C9892DC9BED393C69B73B531862A77F668ACC76151A6F2CA49841773621B8
3DC2AADFFC80|7AC468B209BA2D27ED1B78DAEF0A479143D6BF87CAD997CA44A7F65A42A6A15B75DBCEA5B0D5593FF99FDDBFE33CD151
9202736D2240|6198A5638DFB24177216568F6224CA4E73CC942F9208727D1BC36A04424EC288676E327E9068FFF4C3A6250F75C62DA3
F219BD629820|169E0677CF486B4FCFC6F4CDDFE3097103116AB4FA611E05B3151AB81B0B4FF67F4117F3E5A04DB55E802560F15D7D1D
F3511EE2C4B0|C066BBF3C8222301B03F77CC5BD379E27F86C9B9238591A11D969DAD3500C70D42083EDA45C1F4D4500F48E191EC8E5A
3ECAB6BF7720|08326E68B21C104DD4DA658287482FBC2B5CC9FD56818603A6E2D9EB14EBB1FCB2DD9FBBC459CFBD8DC9DD3463D18243
CD62F688F498|3DECD3CF4BC577FBA2C049823070307EA2D8FB92CB14CDB661C7A640CD43FB9D4E5CD44FE7B45F7DE13FF374FC4231D6
C2CBAA33A9F8|A348F26ACB02651D1E759DB42D69FAA1DD615F0BC92AF4DF53E36EBD29A42E439B713DBC1E6B74544E093153E81AC8FE
C6F50BB74E29|FE34D4AC98F242B98D2D3D79CA6508E39A80F7AF97B5E16DFB7B0068CE3023FFFB854F9F64AC12E68632AE8DDE8F30F9
79F1B4CCC62A00|1FC106C557A929166797AED85B1DD5AD4D8B5959D42EF73C8B28C9CC1F11DAAEF6C056D73006E0C1FF9816874DF1E333
