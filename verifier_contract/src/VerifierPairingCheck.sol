// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Pairing {

    struct ECPoint {
        uint256 x;
        uint256 y;
    }

    struct ECPoint2 {
        uint256 x1;
        uint256 x2;
        uint256 y1;
        uint256 y2;
    }

    uint256 public constant field_modulus = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    function pairing(uint256[24] memory points) public view returns (uint256 success) {
        (bool ok, bytes memory result) = address(8).staticcall(abi.encode(points));
        require(ok, "pairing failed");
        success = abi.decode(result, (uint256));
    }

    function verifier() public view returns (bool result) {
        ECPoint memory A1 = ECPoint(
            8500541046950386545555084973797234505746134092760246356398756868558730993376,
            2728018757505247577599145744834566349470298286886538670623480300640165475336
        );

        ECPoint2 memory B2 = ECPoint2(
            614811356399083613340076117861640930237533867059048572035591919945188572231,
            407513596731636209116223701744982894724875670065054367654203415562053383548,
            20225459237741896907766333525611796225694823438894717812917114930592349384649,
            6599646197841011670943800527194023871199577780963695091771137022800627814386
        );

        ECPoint memory C1 = ECPoint(
            7011711771538146751310900819804679590820264377681734431060390682855291171961,
            10869683322270460627523057894322968893310116613290927008550199847577697543596
        );

        ECPoint memory alpha1 = ECPoint(
            21075150262531933410243350581015787595168186273792137383090173989227707707945,
            16803223452753302947971852296593396982314855353154622521214134510030153364020
        );

        ECPoint2 memory beta2 = ECPoint2(
            9082831086857428347666240538839414598038862953015883554220983146969721132295,
            5946153445888908926765895545450119051763958795422085692866573086426414981726,
            5690917527450736811890845844855066153994393778369678029586091525080118377665,
            5982238848039039019799448545650619183523751194592694323674161867008355731522
        );

        ECPoint memory inner_product1 = ECPoint(
            18203846039728683528457583855779458464804567271139690167314298788231390053471,
            13631105025914729630461642470538628325532158281989889737606409126931242073916
        );

        ECPoint2 memory gamma2 = ECPoint2(
            3422176839735843643577512702252960766443933154095106059593868758352128430632,
            12537673901413488976022732694559403660565095083955194429984527002181624936409,
            5873520565998122640774253709468845083826129197980545879367249660359920981815,
            7842045849139628952740994290150012870613503236269653328239290990207371146041
        );

        ECPoint2 memory delta2 = ECPoint2(
            15406631789566073765258184924288664281353256630222092854167934549758149051822,
            15927868458446079653126710794319459662618357872010717621750847588778804939173,
            12835518685042502042279653518711211224896062119915294166512231593944238642168,
            9346447135837843657377157296380400932320333888697131601581184685634856556180
        );

        uint256 negative_A1_x = A1.x;
        uint256 negative_A1_y = field_modulus - A1.y;

        // pairing(A1, B2) = pairing(alpha1 + beta2) + pairing(inner_product1, gamma2) + pairing(C1, delta2)
        // 0 = -pairing(A1, B2) + pairing(alpha1 + beta2) + pairing(inner_product1, gamma2) + pairing(C1, delta2)
        // 0 = pairing(-A1, B2) + pairing(alpha1 + beta2) + pairing(inner_product1, gamma2) + pairing(C1, delta2)
        uint256[24] memory points = [
            // first pairing
            negative_A1_x,
            negative_A1_y,
            B2.x2,
            B2.x1,
            B2.y2,
            B2.y1,
            // second pairing
            alpha1.x,
            alpha1.y,
            beta2.x2,
            beta2.x1,
            beta2.y2,
            beta2.y1,
            // third pairing
            inner_product1.x,
            inner_product1.y,
            gamma2.x2,
            gamma2.x1,
            gamma2.y2,
            gamma2.y1,
            // fourth pairing
            C1.x,
            C1.y,
            delta2.x2,
            delta2.x1,
            delta2.y2,
            delta2.y1
        ];

        uint256 success = pairing(points);
        result = success == 1;
    }
}