use strict;
use warnings;
use Test::More tests => 19;
use Digest::Keccak qw(keccak_512 keccak_512_hex);

my $len = 0;

while (my $line = <DATA>) {
    chomp $line;
    my ($msg, $digest) = split '\|', $line, 2;
    my $data = pack 'H*', $msg;
    $digest = lc $digest;

    if ($len and not $len % 8) {
        my $md = Digest::Keccak->new(512)->add($data)->hexdigest;
        is($md, $digest, "new/add/hexdigest: $len bits of $msg");
        is(
            keccak_512_hex($data), $digest,
            "keccak_512_hex: $len bits of $msg"
        );
        ok(
            keccak_512($data) eq pack('H*', $digest),
            "keccak_512: $len bits of $msg"
        );
    }
    else {
        TODO:
        eval {
            local $TODO = 'add_bits is not yet implemented';
            my $md = Digest::Keccak->new(512)->add_bits($data, $len)
                ->hexdigest;
            is($md, $digest, "new/add_bits/hexdigest: $msg");
        };
    }
}
continue { $len++ }

__DATA__
00|DF987CFD23FBC92E7E87FAACA300EC3FAA1DBADC678E8EE94A830968F22D920964AB402DC5D0F7B20C9644BE08056555C789D2958BDA3DF98C94BACCEA25D3C1
00|FC5FACE99B8FE87E393BC64951D40F9B341540EB4E0C6505DD9E00465D6494FB596BC95C2FF22404FA10C578418E304828336B007B7AA6528E8BFF31B00A357D
C0|5401920826FFE6554930979EEF44358165118631FBE1A518257D336A239CB0634D601D4D02A18991258B9086EDEE80A615D62C43B5D3397DE22F230501684850
C0|1A6ACEEB5A8541FFD3CE30B35A76288BFD5B03EFB72072C98E44A6C5C9D41A5BD81C748AC22E5967E4F1D40DFFD4E6EDED09ABF05A65383CF9F7B675CC7599E0
80|6A267522ABBF2258CC3BE82EC45797B52AFCE0199375FBFD7F19AA6B6A46007DAE873AFFD4894E963E9778E9D861456D2531EC82AC5964675F8E34D1BE89AAA7
48|46340ACA865D6D6BC99D1152FDD68BE4E2A9A0D7DBC5E658F82E6259A3CFEED36F1C7E529869C6560B2541BC63BBB4AEE03E8B43C3603DF1659817E1015B77AC
50|A1CE902D43D18E28FF3546A6B4D0EA76C302334D7BDD7508D78C90CC95EC390A057FF609BF83BA4B09AA392D7E78A952395B31337FC28ECEF30C26AA3B05A5E5
98|F722832E70DBD1FFA8117A2615C79581C9A90AC895E3C04187B0E7D9F626FCC492B1370453E4EDE76E258144F2D6F34C4F6CFA05DB8A2FEF2352C5FFB2F57C27
CC|208E874297530639B235AF85FA7B1FF9CDE7645F6C061DF702286DFB4A443B8617DD37D87EEB03A066D6412A2EDE14133695A52FD842FBE38CF9856B8426F022
9800|F5CBB148F8BA7AD938C1DDC5DA58C81C15BBA6595CAD063BEE499B7CEECFCFD91C3991D145BAC0E25079818B4E723305B429ADC3FA3163D7A346F0B7BDFA8F9D
9D40|FC859A29D2A961CBC1B6EC3174D41DD5614FC59A46E489B12B72398E19CAEB00A5204F12D69EEF5CA29BE3D91F031260A2217961D865008467B96920F85C1963
AA80|F933F91CE3917BD64E5314DD66F395131CB1ABB839D4FB54335BFA942704A5B756EA70CED73C7B9AC6408EB84E57F431300058CF6F0D0CC047777D880C8F748D
9830|9674094F7AF6F2BA02D5FBC45F1EBABE93EBAE91C9582C967622C409DD866A5FA47AB59263E07FB7412917452EE23080BDEEB32BD6E0F418B58393246336FEDB
5030|7B1F5A01AE32F24CED2B950AC2AD12535C84C1B188D051EF09D51DA3B3F1FF2CCEBAD3659B426B845224897CD7B44F185144CBAB93AADCFF26BC9F1A46519C73
4D24|D9EDFDDB13C26AB3EBBD112270EAF708F0879650E686476955093D7B13934DA53F03DBE4C2E6A7A68419EE41E57D2A5688A0E354E6AC259CA2C7B31B103A57D8
CBDE|41DC07E26E4D88A77B8A4EE0937DDBD0B1875FA06844E02EB844CCFFECEA418A68B3C23852EF88B823133FCA9AEE54D5659F1C3A95163CC4FADF7D84DEB4FE18
41FB|F820F3BFE9F96E5EA41649881A1F3CF854ADF989AC0590F2FB457379737A992AA32D3A8B68BE467CBC7FB3CA5C08971ACD29E5C57C63DFAB0781B0AA3FD024E3
4FF400|3B2675FEA4EA95C5318E1652BFD9305E39BB766AF264071044225E6BE2A017C0145A1CEE4EBB44AA22E97D74BCE90A4EC1CA0F26D8793F72F38C7797409A73E8
FD0440|A5D4B4B1C2E786B0DF512285EB0CED4D269F8D66A59AF7A2848E0A8868CD3768B402E43C1BC5B856DAD0DBF23381C18DF3DACC8C6F7E21CEFB7A9EFD7AEB58ED
424D00|78F42CE97E0BEB6B2194D24EF4A4E80B05416F372C0671C933988DB79F59299AB48CCA35AB2B97CD05722E7BE630AD1221FBA6938703CC233F9A418C44A85512
3FDEE0|4D3EC30F1E7D9CEB6056FDDD815AA1EEB050BF53F03C26223CF7ED7DB0F65981FA7EFBA2A8A2E2865EB9E937D31823F5002C953E1A845C4EA3124C5997AD4ABF
335768|BFB7B5785A2B511EABA2B65B63BF8CEC1B38B2A94E07A9A88E19EA88CC235523BFCBB0AF3364CABC89FD288F72A5FC059C24B24D3B0015A994972D7B77FB737A
051E7C|B73509AD4CA770BE2260C4A5FA0AFBAC17CC2F08CB7A80DBBFF1E2D850AEE6459D013D9C6D6AF75B60A0D457E46BD5726618568FD5810FB4940E483D3641008F
717F8C|D415A18414085BA614461BD1947AFBB1DDF2186C2A49A29541EF944923AD15793BBB9313191DBB1B2E93ECF102DAC61420C5BDB1D0D014FDC609AFA68A26A3E7
1F877C|F24F40618645F3CFBAD985C45E9ED014CA7C495A2464C105A4C005D12DC86029E0AB50132E88B8A7DBAD983A90D455D5D9EE7B75EADA59057DECB93333CE8ADD
EB35CF80|AC68C430F077B46605C6EEEC83EDA1C3C32356BFEB5FEED350F62AA194A5249B668630A752DF6A5A496333FD980AF53CA9C1057A40FE34E142F230120C9316DD
B406C480|B8DB1AF12F7D62BBE7491CBEE471184B86F13100D10828CC06E73EDA2A6DC3D4C88EC17F1A5E6A8752007C19F8348EFEE2F0271E7E5DE5CF65CB09B6FCBBFAFC
CEE88040|4AEC4FB550B4B25CC772B083CD5F3840C266007036A05D3A8676BC22DF040D06697B5475B7DC3CC6A91169007BA87F03215DEBDFA8617A5A185A121B6C2AFDD4
C584DB70|09DF64CAFAC88163BC0819F94E47242ED093FF42B1494D62E320844B404C7A53110E90443F97191E9466B4C41E7680893C40BF8A02A79530C6B27F4EDC817DE3
53587BC8|83161BB5B65CEEA9E95C304122030B0F13F3D48E83EE0D938346E70E96E4A0B40356083593C8424846FA722C9948F1539A308D2F4AD4391552D2EEE46076F9AB
69A305B0|794F22A5D96B6FC75838345A2ECF95E6200A5C03CD561ABCC021B56C1437E92872B68BC838DF3D81CE50D2723A2FB2822D5C5CB44E4C23877DD9EEAF24B9DA91
C9375ECE|12D7FF2D1CA8603BD14821D2B5D2B2C514A0F952FDFEC13DF013462EE18B223905B4C3A1FB82DA3AF4722C17DA16EACE5ABCBCCAA7081009D51CA6FA715986D9
C1ECFDFC|AC5A40C0CA0F9C5EBB2D9478058E5E1E7D6503611DC38B6902E5D6EB972199E1739B723161CCB2D387EA3E1B0A092820040DE941FD8A3B22DA6F9A33262731E4
8D73E8A280|85FAC0F78C221EB4870FDC2DC3D8B616AC89FB2C998B61F100B3ACED1DC49FB5938365E1FF7BC3DBF3402359864A41612C044599289AF5EFD5C4C6C2072F7ADA
06F2522080|78910ACCE9EDB5CBF0E902347EE5781685DA0A769CE853D4E4E99FD7219CE85BB5F1DEAE7029B7C3F27D24F6A4D06FA043DD79682F55B7544D88BA500A4739F2
3EF6C36F20|B890EF66FFA421F4074FA442D98E749ED3DBA78AEA2F5953E6173E218A74FE31F16958578EC6A5E6C5526BA27CE46AE4B7F64F3A542EEA77BBD12BBFB4B05618
0127A1D340|CA1F1C7B5817ADCD01149295BCB407572A5A4E4E7A5945690A6773D5931A9D4E0790992053BA502E1593A36403231C94382412CDB95EC69764B0EFE9233070FA
6A6AB6C210|6F136687AE8D3BC44B689C0B94F621FA54EB1DF4C0D17C75CDF609CDAF0C0E55E2309491729EA6A442439F777D564036FF530E5B867517C93F6558E37CCB58E4
AF3175E160|72F52EB368409B1586E7BC7EBD02C879486C3B4C21FE962C0B7F675E0C12F3E712C9CAE0F8445C7E0A5E75FCE88347298C8C038906F8E0E2C612E43A60EAF2BA
B66609ED86|F580C879825A9004E62733D594012C00DD68CB45BE3040BA81BC540D9A24E5C6C63D7409220EB99EE5A01DA61FD7DA7DBCE5D0A90B7EEC5B7675B2A5A42C79B0
21F134AC57|A71E63BF1859BE634ABC637793A3F46A10C1205CAF8557267C5C36766DF96BB275DBD4A889E4BCA5E1371E9017114D049DC081205D65B22E6EA43B2A91D4C2FB
3DC2AADFFC80|15F59CAEFBB1C189C770EF90077888ED2BC2DB09C2E8774959DDCAFD806B08BD728BCE2DAA2B8B6103AD936AD356075BD2503493B92E917260D6C2ECB0DC71FD
9202736D2240|F929376ECAAA86D5D789F40B70FCDA7B8D55B4591F67DF5843436B0DB9AEC041359D86420F829AF959DBC61B30F35FCC0FBA8F25E1CC0D207C8E340234CE4759
F219BD629820|33EEA0BA1CFD4C77C55D30B3EAC1C65F9811F0026964F9D0419E44A1A42C2C95E4BDFC8D331AD13C3FD15251B7140F288AC1DDE222990F802493BF1B4E56D55D
F3511EE2C4B0|ED6F43DA40FEE15F84423DFC2E86EF02AEFAA23CF2E0305690B4A4F1AF6F4D056902EA924F26F13A01FB0F903B6CB002DCE6BF856D361E32B3258537286B8ABE
3ECAB6BF7720|EE8E35EE84AEE9E80BE391740EC6DC5FA186E76CB5267AC51088B0D64E945DF1540FFFEA818795D4F5CD5B6C681680588709FE0A055FA7ED34A9DDFC45794303
CD62F688F498|5E72C8F272575167E8078C4966DFCA3D43402FAD035DA359D25660613037FD3BD16A857E3951580B0FA4F03AE0D32A463C2CC65DF5398EB96A69F8736C7B7EEF
C2CBAA33A9F8|F80C11AAC63E42A48A730D2029DF4B830E04B14EFD27EBED8D3C1ED55537FA054BB1ADB2DF93301F9304B8008AA61080818243E7665EE0AADD9FEEE2ACA3070E
C6F50BB74E29|647BA6B644136A2F759A17BD313C5BA69E4E62BEAEDA7EFBBF0FCC62A7D881AD272D1D9949F28542CD0CC4B7B3FF1CC5041355FAF161D8732E6796298F54A16C
79F1B4CCC62A00|1989481DF64116D1CF48528A1526BEDBE92191F764712B6EED0ADD5BA065CA4460A7B6D3C007D80CB4A999850AF8FED92AE3784F392FF7DD5F66D7DE9919247A
